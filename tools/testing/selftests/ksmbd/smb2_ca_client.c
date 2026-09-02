// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal SMB3 client for exercising ksmbd persistent handles on a
 * Continuously Available share.
 *
 * This is deliberately not a general purpose SMB client.  It speaks just
 * enough of SMB 3.0 to grant, abandon and reconnect a persistent handle, which
 * is something no ordinary client can be made to do on demand:
 *
 *   - the Linux SMB client never sends a DURABLE_HANDLE_RECONNECT_V2 create
 *     context, it reopens files by path, so it cannot show that a handle was
 *     recovered rather than simply reopened;
 *   - smbtorture can disconnect and reconnect within one test, but it cannot
 *     restart the server in between, which is exactly what has to happen to
 *     test recovery from on-disk state.
 *
 * Authentication is deliberately the guest path (raw NTLMSSP, unknown user,
 * empty NT/LM response, which ksmbd maps to the guest account when the server
 * is configured with "map to guest = bad user").  That keeps the client free of
 * NTLMv2 and SMB3 signing, neither of which is what is under test here.
 *
 * Each subcommand is one step of a scenario; the shell driver sequences them
 * and restarts the server between steps.  Handle state is passed between
 * invocations through a small state file, standing in for what a real client
 * keeps in memory across a server outage.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SMB2_PROTO_NUMBER	0x424d53feU	/* "\xFESMB" */
#define SMB_PORT		445

#define SMB2_NEGOTIATE		0x0000
#define SMB2_SESSION_SETUP	0x0001
#define SMB2_TREE_CONNECT	0x0003
#define SMB2_CREATE		0x0005
#define SMB2_CLOSE		0x0006
#define SMB2_READ		0x0008
#define SMB2_WRITE		0x0009

#define SMB30_PROT_ID		0x0300

#define STATUS_SUCCESS			0x00000000U
#define STATUS_MORE_PROCESSING_REQUIRED	0xC0000016U
#define STATUS_FILE_NOT_AVAILABLE	0xC0000467U

#define SMB2_NEGOTIATE_SIGNING_ENABLED	0x0001

#define SMB2_GLOBAL_CAP_DFS		0x00000001
#define SMB2_GLOBAL_CAP_LEASING		0x00000002
#define SMB2_GLOBAL_CAP_LARGE_MTU	0x00000004
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010

#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY 0x00000010

#define SMB2_SESSION_FLAG_IS_GUEST	0x0001

#define SMB2_OPLOCK_LEVEL_NONE		0x00
#define SMB2_OPLOCK_LEVEL_BATCH		0x09

#define FILE_SHARE_ALL			0x00000007
#define FILE_OPEN_IF			0x00000003
#define FILE_OPEN			0x00000001
#define FILE_NON_DIRECTORY_FILE		0x00000040
#define DESIRED_ACCESS_RW		0x0012019FU

#define SMB2_DHANDLE_FLAG_PERSISTENT	0x00000002

/* Mirrors ksmbd's own cap: MS-SMB2 caps a durable timeout at 300 s. */
#define DURABLE_TIMEOUT_MS		120000

#define MAX_PDU				(1 << 17)

struct state_file {
	uint64_t	persistent_id;
	uint64_t	volatile_id;
	uint8_t		create_guid[16];
	uint8_t		client_guid[16];
};

struct smb_conn {
	int		fd;
	uint64_t	mid;
	uint64_t	session_id;
	uint32_t	tree_id;
	uint32_t	server_caps;
	uint32_t	share_caps;
	uint8_t		client_guid[16];
	uint8_t		buf[MAX_PDU];
	size_t		rsp_len;	/* SMB2 PDU length, excluding NBSS */
};

static const char *prog;

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void put_le16(void *p, uint16_t v)
{
	uint8_t *b = p;

	b[0] = v & 0xff;
	b[1] = v >> 8;
}

static void put_le32(void *p, uint32_t v)
{
	uint8_t *b = p;

	b[0] = v & 0xff;
	b[1] = (v >> 8) & 0xff;
	b[2] = (v >> 16) & 0xff;
	b[3] = v >> 24;
}

static void put_le64(void *p, uint64_t v)
{
	put_le32(p, (uint32_t)v);
	put_le32((uint8_t *)p + 4, (uint32_t)(v >> 32));
}

static uint16_t get_le16(const void *p)
{
	const uint8_t *b = p;

	return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static uint32_t get_le32(const void *p)
{
	const uint8_t *b = p;

	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t get_le64(const void *p)
{
	return (uint64_t)get_le32(p) | ((uint64_t)get_le32((const uint8_t *)p + 4) << 32);
}

/* Length-prefixed UTF-16LE, ASCII input only. */
static size_t to_utf16le(uint8_t *dst, const char *src)
{
	size_t n = 0;

	while (*src) {
		dst[n++] = (uint8_t)*src++;
		dst[n++] = 0;
	}
	return n;
}

static void fill_random(uint8_t *p, size_t len)
{
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0 || read(fd, p, len) != (ssize_t)len)
		die("cannot read /dev/urandom: %s", strerror(errno));
	close(fd);
}

static void xsend(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len) {
		ssize_t n = send(fd, p, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("send: %s", strerror(errno));
		}
		p += n;
		len -= n;
	}
}

static bool xrecv(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len) {
		ssize_t n = recv(fd, p, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("recv: %s", strerror(errno));
		}
		if (n == 0)
			return false;
		p += n;
		len -= n;
	}
	return true;
}

static int conn_open(struct smb_conn *c, const char *host)
{
	struct sockaddr_in sa = {};
	int one = 1;

	memset(c, 0, sizeof(*c));
	c->mid = 0;

	c->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (c->fd < 0)
		die("socket: %s", strerror(errno));

	setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	sa.sin_family = AF_INET;
	sa.sin_port = htons(SMB_PORT);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		die("bad address '%s'", host);

	if (connect(c->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("connect to %s:%d: %s", host, SMB_PORT, strerror(errno));
	return 0;
}

static void conn_close(struct smb_conn *c)
{
	if (c->fd >= 0)
		close(c->fd);
	c->fd = -1;
}

/*
 * Build an SMB2 header at the front of @c->buf and return the offset of the
 * request body that follows it.
 */
static size_t req_start(struct smb_conn *c, uint16_t cmd)
{
	uint8_t *h = c->buf + 4;

	memset(c->buf, 0, MAX_PDU);
	put_le32(h + 0, SMB2_PROTO_NUMBER);
	put_le16(h + 4, 64);			/* StructureSize */
	put_le16(h + 6, 1);			/* CreditCharge */
	put_le32(h + 8, 0);			/* Status */
	put_le16(h + 12, cmd);
	put_le16(h + 14, 64);			/* CreditRequest */
	put_le32(h + 16, 0);			/* Flags */
	put_le32(h + 20, 0);			/* NextCommand */
	/*
	 * The sequence window starts at [0, 1), so the very first request --
	 * NEGOTIATE -- has to be MessageId 0.
	 */
	put_le64(h + 24, c->mid++);
	put_le32(h + 32, 0);			/* Reserved / ProcessId */
	put_le32(h + 36, c->tree_id);
	put_le64(h + 40, c->session_id);
	return 4 + 64;
}

/*
 * Send the request occupying @c->buf[4 .. 4 + len) and read the reply back into
 * @c->buf.  Returns the NT status; the reply body starts at c->buf + 64.
 */
static uint32_t req_xchg(struct smb_conn *c, size_t len)
{
	uint8_t nb[4];
	uint32_t n;

	c->buf[0] = 0;
	c->buf[1] = (len >> 16) & 0xff;
	c->buf[2] = (len >> 8) & 0xff;
	c->buf[3] = len & 0xff;
	xsend(c->fd, c->buf, len + 4);

	if (!xrecv(c->fd, nb, sizeof(nb)))
		die("server closed the connection");
	n = ((uint32_t)nb[1] << 16) | ((uint32_t)nb[2] << 8) | nb[3];
	if (n < 64 || n > MAX_PDU)
		die("bogus NBSS length %u", n);
	if (!xrecv(c->fd, c->buf, n))
		die("short read of %u byte PDU", n);
	c->rsp_len = n;

	if (get_le32(c->buf) != SMB2_PROTO_NUMBER)
		die("reply is not SMB2");
	return get_le32(c->buf + 8);
}

static const uint8_t *rsp_body(struct smb_conn *c, size_t min_len)
{
	if (c->rsp_len < 64 + min_len)
		die("reply body is %zu bytes, need %zu",
		    c->rsp_len - 64, min_len);
	return c->buf + 64;
}

static void do_negotiate(struct smb_conn *c)
{
	size_t off = req_start(c, SMB2_NEGOTIATE);
	uint8_t *b = c->buf + off;
	const uint8_t *r;
	uint32_t status;

	put_le16(b + 0, 36);			/* StructureSize */
	put_le16(b + 2, 1);			/* DialectCount */
	put_le16(b + 4, SMB2_NEGOTIATE_SIGNING_ENABLED);
	put_le16(b + 6, 0);			/* Reserved */
	put_le32(b + 8, SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING |
			SMB2_GLOBAL_CAP_LARGE_MTU);
	memcpy(b + 12, c->client_guid, 16);
	put_le64(b + 28, 0);			/* ClientStartTime */
	put_le16(b + 36, SMB30_PROT_ID);

	status = req_xchg(c, off - 4 + 38);
	if (status != STATUS_SUCCESS)
		die("NEGOTIATE failed: 0x%08x", status);

	r = rsp_body(c, 64);
	if (get_le16(r + 4) != SMB30_PROT_ID)
		die("server picked dialect 0x%04x, expected 0x%04x",
		    get_le16(r + 4), SMB30_PROT_ID);
	c->server_caps = get_le32(r + 24);
}

/*
 * Guest session setup.  Two round trips of raw NTLMSSP: a NEGOTIATE message to
 * draw out the challenge, then an AUTHENTICATE message naming a user the server
 * does not know and carrying no response fields at all.
 */
static void do_session_setup(struct smb_conn *c, const char *user)
{
	static const uint8_t sig[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };
	/* UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY */
	const uint32_t flags = 0x00000001 | 0x00000004 | 0x00000200 |
			       0x00008000 | 0x00080000;
	size_t off, blob_off, n;
	uint8_t *b, *blob;
	uint32_t status;
	uint16_t sess_flags;
	const uint8_t *r;

	/* NTLMSSP_NEGOTIATE */
	off = req_start(c, SMB2_SESSION_SETUP);
	b = c->buf + off;
	blob_off = 24;
	blob = b + blob_off;

	memcpy(blob, sig, 8);
	put_le32(blob + 8, 1);			/* NtLmNegotiate */
	put_le32(blob + 12, flags);
	/* DomainName and WorkstationName absent */

	put_le16(b + 0, 25);			/* StructureSize */
	b[2] = 0;				/* Flags */
	b[3] = 0;				/* SecurityMode: signing off */
	put_le32(b + 4, 0);			/* Capabilities */
	put_le32(b + 8, 0);			/* Channel */
	put_le16(b + 12, 64 + blob_off);	/* SecurityBufferOffset */
	put_le16(b + 14, 32);			/* SecurityBufferLength */
	put_le64(b + 16, 0);			/* PreviousSessionId */

	status = req_xchg(c, off - 4 + blob_off + 32);
	if (status != STATUS_MORE_PROCESSING_REQUIRED)
		die("SESSION_SETUP (negotiate) failed: 0x%08x", status);
	c->session_id = get_le64(c->buf + 40);

	/* NTLMSSP_AUTHENTICATE, everything empty but the user name. */
	off = req_start(c, SMB2_SESSION_SETUP);
	b = c->buf + off;
	blob = b + blob_off;

	memcpy(blob, sig, 8);
	put_le32(blob + 8, 3);			/* NtLmAuthenticate */
	/* LmChallengeResponse, NtChallengeResponse: empty */
	put_le16(blob + 12, 0);
	put_le16(blob + 14, 0);
	put_le32(blob + 16, 64);
	put_le16(blob + 20, 0);
	put_le16(blob + 22, 0);
	put_le32(blob + 24, 64);
	/* DomainName: empty */
	put_le16(blob + 28, 0);
	put_le16(blob + 30, 0);
	put_le32(blob + 32, 64);
	/* UserName */
	n = to_utf16le(blob + 64, user);
	put_le16(blob + 36, (uint16_t)n);
	put_le16(blob + 38, (uint16_t)n);
	put_le32(blob + 40, 64);
	/* WorkstationName, SessionKey: empty */
	put_le16(blob + 44, 0);
	put_le16(blob + 46, 0);
	put_le32(blob + 48, 64 + n);
	put_le16(blob + 52, 0);
	put_le16(blob + 54, 0);
	put_le32(blob + 56, 64 + n);
	put_le32(blob + 60, flags);

	put_le16(b + 0, 25);
	b[2] = 0;
	b[3] = 0;
	put_le32(b + 4, 0);
	put_le32(b + 8, 0);
	put_le16(b + 12, 64 + blob_off);
	put_le16(b + 14, (uint16_t)(64 + n));
	put_le64(b + 16, 0);

	status = req_xchg(c, off - 4 + blob_off + 64 + n);
	if (status != STATUS_SUCCESS)
		die("SESSION_SETUP (authenticate) failed: 0x%08x -- does the\n"
		    "server have 'map to guest = bad user' and a guest account?",
		    status);

	r = rsp_body(c, 8);
	sess_flags = get_le16(r + 2);
	if (!(sess_flags & SMB2_SESSION_FLAG_IS_GUEST))
		die("session is not a guest session (flags 0x%04x); this client cannot sign",
		    sess_flags);
}

static void do_tree_connect(struct smb_conn *c, const char *host,
			    const char *share)
{
	char path[512];
	size_t off = req_start(c, SMB2_TREE_CONNECT);
	uint8_t *b = c->buf + off;
	const uint8_t *r;
	uint32_t status;
	size_t n;

	snprintf(path, sizeof(path), "\\\\%s\\%s", host, share);
	n = to_utf16le(b + 8, path);

	put_le16(b + 0, 9);			/* StructureSize */
	put_le16(b + 2, 0);			/* Flags/Reserved */
	put_le16(b + 4, 64 + 8);		/* PathOffset */
	put_le16(b + 6, (uint16_t)n);		/* PathLength */

	status = req_xchg(c, off - 4 + 8 + n);
	if (status != STATUS_SUCCESS)
		die("TREE_CONNECT to %s failed: 0x%08x", share, status);

	c->tree_id = get_le32(c->buf + 36);
	r = rsp_body(c, 16);
	c->share_caps = get_le32(r + 8);
}

/*
 * CREATE.  @dh2q_flags non-zero adds a DURABLE_HANDLE_REQUEST_V2 context with
 * those flags; @dh2c asks instead for DURABLE_HANDLE_RECONNECT_V2 using
 * @st.  On success the granted ids are returned through @out.
 */
static uint32_t do_create(struct smb_conn *c, const char *name,
			  uint8_t oplock, uint32_t disposition,
			  uint32_t dh2q_flags, const struct state_file *dh2c,
			  struct state_file *out, uint32_t *dh2q_rsp_flags)
{
	size_t off = req_start(c, SMB2_CREATE);
	uint8_t *b = c->buf + off;
	uint8_t *p;
	size_t name_len, ctx_off, ctx_len = 0, body;
	const uint8_t *r;
	uint32_t status;

	name_len = to_utf16le(b + 56, name);
	/* Create contexts must start 8-byte aligned within the PDU. */
	ctx_off = (56 + name_len + 7) & ~(size_t)7;

	put_le16(b + 0, 57);			/* StructureSize */
	b[2] = 0;				/* SecurityFlags */
	b[3] = oplock;				/* RequestedOplockLevel */
	put_le32(b + 4, 2);			/* ImpersonationLevel */
	put_le64(b + 8, 0);			/* SmbCreateFlags */
	put_le64(b + 16, 0);			/* Reserved */
	put_le32(b + 24, DESIRED_ACCESS_RW);
	put_le32(b + 28, 0);			/* FileAttributes */
	put_le32(b + 32, FILE_SHARE_ALL);
	put_le32(b + 36, disposition);
	put_le32(b + 40, FILE_NON_DIRECTORY_FILE);
	put_le16(b + 44, (uint16_t)(64 + 56));	/* NameOffset */
	put_le16(b + 46, (uint16_t)name_len);

	p = b + ctx_off;
	if (dh2c) {
		/* Next(0) NameOffset(16) NameLength(4) DataOffset(24) DataLength(36) */
		put_le32(p + 0, 0);
		put_le16(p + 4, 16);
		put_le16(p + 6, 4);
		put_le16(p + 8, 0);
		put_le16(p + 10, 24);
		put_le32(p + 12, 36);
		memcpy(p + 16, "DH2C", 4);
		put_le64(p + 24, dh2c->persistent_id);
		put_le64(p + 32, dh2c->volatile_id);
		memcpy(p + 40, dh2c->create_guid, 16);
		put_le32(p + 56, dh2q_flags);
		ctx_len = 60;
	} else if (dh2q_flags || oplock == SMB2_OPLOCK_LEVEL_BATCH) {
		put_le32(p + 0, 0);
		put_le16(p + 4, 16);
		put_le16(p + 6, 4);
		put_le16(p + 8, 0);
		put_le16(p + 10, 24);
		put_le32(p + 12, 32);
		memcpy(p + 16, "DH2Q", 4);
		put_le32(p + 24, DURABLE_TIMEOUT_MS);
		put_le32(p + 28, dh2q_flags);
		put_le64(p + 32, 0);		/* Reserved */
		memcpy(p + 40, out->create_guid, 16);
		ctx_len = 56;
	}

	if (ctx_len) {
		put_le32(b + 48, (uint32_t)(64 + ctx_off));
		put_le32(b + 52, (uint32_t)ctx_len);
		body = ctx_off + ctx_len;
	} else {
		put_le32(b + 48, 0);
		put_le32(b + 52, 0);
		body = 56 + name_len;
	}

	status = req_xchg(c, off - 4 + body);
	if (status != STATUS_SUCCESS)
		return status;

	r = rsp_body(c, 88);
	out->persistent_id = get_le64(r + 64);
	out->volatile_id = get_le64(r + 72);

	if (dh2q_rsp_flags) {
		uint32_t coff = get_le32(r + 80);
		uint32_t clen = get_le32(r + 84);

		*dh2q_rsp_flags = 0;
		/*
		 * Walk the response contexts looking for DH2Q; its flags say
		 * whether the server actually made the handle persistent.
		 */
		while (clen >= 16 && coff + 16 <= c->rsp_len) {
			const uint8_t *cc = c->buf + coff;
			uint32_t next = get_le32(cc + 0);
			uint16_t noff = get_le16(cc + 4);
			uint16_t nlen = get_le16(cc + 6);
			uint16_t doff = get_le16(cc + 10);
			uint32_t dlen = get_le32(cc + 12);

			if (nlen == 4 && coff + noff + 4 <= c->rsp_len &&
			    !memcmp(cc + noff, "DH2Q", 4) && dlen >= 8 &&
			    coff + doff + 8 <= c->rsp_len)
				*dh2q_rsp_flags = get_le32(cc + doff + 4);

			if (!next)
				break;
			coff += next;
		}
	}
	return STATUS_SUCCESS;
}

static void do_write(struct smb_conn *c, const struct state_file *st,
		     const char *data)
{
	size_t off = req_start(c, SMB2_WRITE);
	uint8_t *b = c->buf + off;
	size_t len = strlen(data);
	uint32_t status;

	put_le16(b + 0, 49);			/* StructureSize */
	put_le16(b + 2, (uint16_t)(64 + 48));	/* DataOffset */
	put_le32(b + 4, (uint32_t)len);
	put_le64(b + 8, 0);			/* Offset */
	put_le64(b + 16, st->persistent_id);
	put_le64(b + 24, st->volatile_id);
	put_le32(b + 32, 0);			/* Channel */
	put_le32(b + 36, 0);			/* RemainingBytes */
	put_le16(b + 40, 0);
	put_le16(b + 42, 0);
	put_le32(b + 44, 0);			/* Flags */
	memcpy(b + 48, data, len);

	status = req_xchg(c, off - 4 + 48 + len);
	if (status != STATUS_SUCCESS)
		die("WRITE failed: 0x%08x", status);
	if (get_le32(rsp_body(c, 16) + 4) != len)
		die("WRITE wrote %u of %zu bytes",
		    get_le32(rsp_body(c, 16) + 4), len);
}

static void do_read_expect(struct smb_conn *c, const struct state_file *st,
			   const char *expect)
{
	size_t off = req_start(c, SMB2_READ);
	uint8_t *b = c->buf + off;
	size_t len = strlen(expect);
	const uint8_t *r;
	uint32_t status, dlen;
	uint8_t doff;

	put_le16(b + 0, 49);			/* StructureSize */
	b[2] = 0;				/* Padding */
	b[3] = 0;				/* Flags */
	put_le32(b + 4, (uint32_t)len);
	put_le64(b + 8, 0);			/* Offset */
	put_le64(b + 16, st->persistent_id);
	put_le64(b + 24, st->volatile_id);
	put_le32(b + 32, 1);			/* MinimumCount */
	put_le32(b + 36, 0);			/* Channel */
	put_le32(b + 40, 0);			/* RemainingBytes */
	put_le16(b + 44, 0);
	put_le16(b + 46, 0);

	status = req_xchg(c, off - 4 + 49);
	if (status != STATUS_SUCCESS)
		die("READ failed: 0x%08x", status);

	r = rsp_body(c, 16);
	doff = r[2];
	dlen = get_le32(r + 4);
	if (dlen != len || doff + dlen > c->rsp_len)
		die("READ returned %u bytes, expected %zu", dlen, len);
	if (memcmp(c->buf + doff, expect, len))
		die("READ returned unexpected data");
}

static void do_close(struct smb_conn *c, const struct state_file *st)
{
	size_t off = req_start(c, SMB2_CLOSE);
	uint8_t *b = c->buf + off;
	uint32_t status;

	put_le16(b + 0, 24);			/* StructureSize */
	put_le16(b + 2, 0);			/* Flags */
	put_le32(b + 4, 0);			/* Reserved */
	put_le64(b + 8, st->persistent_id);
	put_le64(b + 16, st->volatile_id);

	status = req_xchg(c, off - 4 + 24);
	if (status != STATUS_SUCCESS)
		die("CLOSE failed: 0x%08x", status);
}

static void state_save(const char *path, const struct state_file *st)
{
	FILE *f = fopen(path, "w");

	if (!f)
		die("cannot write %s: %s", path, strerror(errno));
	fprintf(f, "%llu %llu ", (unsigned long long)st->persistent_id,
		(unsigned long long)st->volatile_id);
	for (int i = 0; i < 16; i++)
		fprintf(f, "%02x", st->create_guid[i]);
	fputc(' ', f);
	for (int i = 0; i < 16; i++)
		fprintf(f, "%02x", st->client_guid[i]);
	fputc('\n', f);
	if (fclose(f))
		die("cannot write %s: %s", path, strerror(errno));
}

static void hex_to_bin(const char *s, uint8_t *out, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		unsigned int v;

		if (sscanf(s + 2 * i, "%2x", &v) != 1)
			die("malformed hex in state file");
		out[i] = (uint8_t)v;
	}
}

static void state_load(const char *path, struct state_file *st)
{
	char cg[40], clg[40];
	unsigned long long pid, vid;
	FILE *f = fopen(path, "r");

	if (!f)
		die("cannot read %s: %s", path, strerror(errno));
	if (fscanf(f, "%llu %llu %39s %39s", &pid, &vid, cg, clg) != 4)
		die("malformed state file %s", path);
	fclose(f);

	if (strlen(cg) != 32 || strlen(clg) != 32)
		die("malformed guid in state file %s", path);
	st->persistent_id = pid;
	st->volatile_id = vid;
	hex_to_bin(cg, st->create_guid, 16);
	hex_to_bin(clg, st->client_guid, 16);
}

static void require_ca(struct smb_conn *c, const char *share)
{
	if (!(c->server_caps & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES))
		die("server does not advertise SMB2_GLOBAL_CAP_PERSISTENT_HANDLES");
	if (!(c->share_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY))
		die("share '%s' does not advertise SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY",
		    share);
}

static void usage(void)
{
	fprintf(stderr,
		"%s: <command> <host> <share> [args]\n"
		"\n"
		"  caps      <host> <share>\n"
		"        report negotiated capabilities; exit non-zero unless the\n"
		"        share offers Continuous Availability\n"
		"  nocaps    <host> <share>\n"
		"        the inverse: fail if the share offers CA\n"
		"  grant     <host> <share> <file> <state> <data>\n"
		"        open <file> with a persistent handle, write <data>, then\n"
		"        drop the connection leaving the handle disconnected\n"
		"  reconnect <host> <share> <file> <state> <data>\n"
		"        reconnect the handle in <state> with DH2C and verify\n"
		"        <data> is still readable through it, then close it\n"
		"  open      <host> <share> <file>\n"
		"        plain open of an existing file, expected to succeed\n"
		"  conflict  <host> <share> <file>\n"
		"        plain open from a different client, expected to be\n"
		"        fenced with STATUS_FILE_NOT_AVAILABLE\n"
		"  denied    <host> <share> <file>\n"
		"        open <file> expecting the server to refuse it\n"
		"  nonpersistent <host> <share> <file> <state>\n"
		"        request a persistent handle and require that the server\n"
		"        grants a durable, non-persistent one instead\n",
		prog);
	exit(2);
}

int main(int argc, char **argv)
{
	const char *cmd, *host, *share, *user = "ksmbd-ca-nobody";
	struct state_file st = {};
	struct smb_conn c;
	uint32_t status;

	prog = argv[0];
	if (argc < 4)
		usage();

	cmd = argv[1];
	host = argv[2];
	share = argv[3];

	fill_random(st.client_guid, sizeof(st.client_guid));
	fill_random(st.create_guid, sizeof(st.create_guid));

	if (!strcmp(cmd, "caps") || !strcmp(cmd, "nocaps")) {
		bool want = !strcmp(cmd, "caps");

		conn_open(&c, host);
		memcpy(c.client_guid, st.client_guid, 16);
		do_negotiate(&c);
		do_session_setup(&c, user);
		do_tree_connect(&c, host, share);
		printf("server_caps=0x%08x share_caps=0x%08x\n",
		       c.server_caps, c.share_caps);
		if (want)
			require_ca(&c, share);
		else if (c.share_caps & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY)
			die("share '%s' unexpectedly advertises CA", share);
		conn_close(&c);
		return 0;
	}

	if (!strcmp(cmd, "grant") || !strcmp(cmd, "nonpersistent")) {
		bool want_persistent = !strcmp(cmd, "grant");
		const char *file, *statepath, *data = NULL;
		uint32_t rsp_flags = 0;

		if (argc < (want_persistent ? 7 : 6))
			usage();
		file = argv[4];
		statepath = argv[5];
		if (want_persistent)
			data = argv[6];

		conn_open(&c, host);
		memcpy(c.client_guid, st.client_guid, 16);
		do_negotiate(&c);
		do_session_setup(&c, user);
		do_tree_connect(&c, host, share);
		if (want_persistent)
			require_ca(&c, share);

		status = do_create(&c, file, SMB2_OPLOCK_LEVEL_BATCH,
				   FILE_OPEN_IF, SMB2_DHANDLE_FLAG_PERSISTENT,
				   NULL, &st, &rsp_flags);
		if (status != STATUS_SUCCESS)
			die("CREATE of %s failed: 0x%08x", file, status);

		if (want_persistent) {
			if (!(rsp_flags & SMB2_DHANDLE_FLAG_PERSISTENT))
				die("granted, but not persistent (DH2Q flags 0x%08x)",
				    rsp_flags);
			do_write(&c, &st, data);
			state_save(statepath, &st);
			printf("granted persistent handle pid=0x%llx vid=0x%llx\n",
			       (unsigned long long)st.persistent_id,
			       (unsigned long long)st.volatile_id);
			/*
			 * Drop the connection without closing the handle: this
			 * is the disconnect a persistent handle must survive.
			 */
			conn_close(&c);
			return 0;
		}

		if (rsp_flags & SMB2_DHANDLE_FLAG_PERSISTENT)
			die("server granted a persistent handle on a share that does not offer CA");
		printf("granted durable non-persistent handle (DH2Q response flags 0x%08x)\n",
		       rsp_flags);
		state_save(statepath, &st);
		do_close(&c, &st);
		conn_close(&c);
		return 0;
	}

	if (!strcmp(cmd, "reconnect")) {
		struct state_file want;
		const char *file, *statepath, *data;
		uint32_t rsp_flags = 0;

		if (argc < 7)
			usage();
		file = argv[4];
		statepath = argv[5];
		data = argv[6];
		state_load(statepath, &want);

		conn_open(&c, host);
		/* The same ClientGuid: a handle only comes back to its owner. */
		memcpy(c.client_guid, want.client_guid, 16);
		do_negotiate(&c);
		do_session_setup(&c, user);
		do_tree_connect(&c, host, share);
		require_ca(&c, share);

		memcpy(st.create_guid, want.create_guid, 16);
		status = do_create(&c, file, SMB2_OPLOCK_LEVEL_BATCH, FILE_OPEN,
				   SMB2_DHANDLE_FLAG_PERSISTENT, &want, &st,
				   &rsp_flags);
		if (status != STATUS_SUCCESS)
			die("DH2C reconnect of pid=0x%llx failed: 0x%08x",
			    (unsigned long long)want.persistent_id, status);
		if (st.persistent_id != want.persistent_id)
			die("reconnect returned persistent id 0x%llx, expected 0x%llx",
			    (unsigned long long)st.persistent_id,
			    (unsigned long long)want.persistent_id);

		do_read_expect(&c, &st, data);
		printf("reconnected persistent handle pid=0x%llx, data intact\n",
		       (unsigned long long)st.persistent_id);
		do_close(&c, &st);
		conn_close(&c);
		return 0;
	}

	if (!strcmp(cmd, "open")) {
		const char *file;

		if (argc < 5)
			usage();
		file = argv[4];

		conn_open(&c, host);
		/* A fresh ClientGuid: a different client entirely. */
		memcpy(c.client_guid, st.client_guid, 16);
		do_negotiate(&c);
		do_session_setup(&c, user);
		do_tree_connect(&c, host, share);

		status = do_create(&c, file, SMB2_OPLOCK_LEVEL_NONE, FILE_OPEN,
				   0, NULL, &st, NULL);
		if (status != STATUS_SUCCESS)
			die("open of %s failed: 0x%08x", file, status);
		printf("opened %s\n", file);
		do_close(&c, &st);
		conn_close(&c);
		return 0;
	}

	if (!strcmp(cmd, "conflict") || !strcmp(cmd, "denied")) {
		bool fenced = !strcmp(cmd, "conflict");
		const char *file;

		if (argc < 5)
			usage();
		file = argv[4];

		conn_open(&c, host);
		/* A fresh ClientGuid: a different client entirely. */
		memcpy(c.client_guid, st.client_guid, 16);
		do_negotiate(&c);
		do_session_setup(&c, user);
		do_tree_connect(&c, host, share);

		status = do_create(&c, file, SMB2_OPLOCK_LEVEL_NONE, FILE_OPEN,
				   0, NULL, &st, NULL);
		if (status == STATUS_SUCCESS)
			die("open of %s succeeded, expected it to be refused",
			    file);
		if (fenced && status != STATUS_FILE_NOT_AVAILABLE)
			die("open of %s failed with 0x%08x, expected FILE_NOT_AVAILABLE (0x%08x)",
			    file, status, STATUS_FILE_NOT_AVAILABLE);
		printf("open of %s refused with 0x%08x as expected\n",
		       file, status);
		conn_close(&c);
		return 0;
	}

	usage();
	return 2;
}
