/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * On-disk state store for SMB3 persistent handles on Continuously
 * Available (CA) shares.
 */

#ifndef __KSMBD_CA_STORE_H__
#define __KSMBD_CA_STORE_H__

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/types.h>

struct file;
struct ksmbd_file;
struct ksmbd_share_config;
struct ksmbd_user;
struct ksmbd_work;

/*
 * Per-share directory holding the CA state.  It lives inside the share so
 * that the state travels with the exported data, and is vetoed on CA shares
 * (see ksmbd_ca_veto_patterns()) so clients can neither see nor modify it.
 *
 * Two journal slots are used as a ping-pong pair: compaction rewrites the
 * inactive slot and only then stamps its header with a higher generation, so
 * a crash at any point leaves at least one complete, older-or-equal slot.
 */
#define KSMBD_CA_DIR			".ksmbd-ca"
#define KSMBD_CA_NR_SLOTS		2

#define KSMBD_CA_HDR_MAGIC		0x4143534bU	/* "KSCA" */
#define KSMBD_CA_REC_MAGIC		0x5243534bU	/* "KSCR" */
#define KSMBD_CA_VERSION		1
#define KSMBD_CA_HDR_SIZE		64
/* Bounds a single record, i.e. the longest share-relative name plus owner. */
#define KSMBD_CA_REC_MAX		(PATH_MAX + 512)
/* Zeroed bytes written after the last record so replay knows where to stop. */
#define KSMBD_CA_TERM_SIZE		8
/* Compact once this many records have piled up since the last compaction. */
#define KSMBD_CA_COMPACT_MIN		64

/*
 * Slot header.  @crc covers the header from @version onwards, so a torn
 * header is detected and the slot is ignored.  The header is always written
 * after the records it describes.
 */
struct ksmbd_ca_hdr {
	__le32	magic;
	__le32	crc;
	__le16	version;
	__le16	hdr_size;
	__le64	generation;
	__le64	nr_records;
	__u8	reserved[36];
} __packed;

/* ksmbd_ca_rec.flags */
#define KSMBD_CA_F_CLOSED		0x00000001 /* tombstone */
#define KSMBD_CA_F_DISCONNECTED		0x00000002 /* awaiting reconnect */
#define KSMBD_CA_F_LEASE		0x00000004
#define KSMBD_CA_F_DIR			0x00000008
#define KSMBD_CA_F_REPLAY_CONSUMED	0x00000010
/*
 * The record carries the opener's identity.  Needed as its own flag because a
 * zero-length owner name is a legitimate identity (a mapped guest account can
 * have one) and must not be confused with "no owner recorded", which would make
 * the handle unreconnectable.
 */
#define KSMBD_CA_F_OWNER		0x00000020

/*
 * One persistent open.  Records are appended, never updated in place; the
 * last record for a given @persistent_id wins, and a record carrying
 * KSMBD_CA_F_CLOSED retires the id.  @crc covers the record from @len
 * onwards, so a torn append is detected during replay and terminates it.
 */
struct ksmbd_ca_rec {
	__le32	magic;
	__le32	crc;
	__le32	len;			/* whole record, 8-byte aligned */
	__le32	flags;

	__le64	persistent_id;
	__le64	volatile_id;		/* last volatile id, for DH2C/DHnC */

	__u8	create_guid[16];
	__u8	client_guid[16];
	__u8	app_instance_id[16];

	__le32	daccess;
	__le32	saccess;
	__le32	coption;
	__le32	cdoption;
	__le32	file_attributes;
	__le32	create_action;

	__le64	create_time;
	__le64	change_time;
	__le64	itime;
	__le64	allocation_size;

	__le32	durable_timeout;	/* milliseconds */
	__le32	oplock_level;
	__le64	expires_at;		/* seconds, CLOCK_REALTIME; 0 = never */

	__le32	lease_state;
	__le32	lease_flags;
	__le64	lease_duration;
	__le16	lease_epoch;
	__le16	lease_version;
	__u8	lease_key[16];
	__u8	parent_lease_key[16];

	__le32	uid;			/* opener's security context */
	__le32	gid;

	__le16	name_len;		/* share-relative path, no NUL */
	__le16	owner_len;		/* account name, no NUL */
	__le32	reserved;
	__u8	payload[];
} __packed;

/*
 * Per-share journal.  Refcounted because a disconnected persistent handle
 * outlives the tree connect, and therefore the share config, that created it.
 */
struct ksmbd_ca_store {
	struct kref		kref;
	struct list_head	list;
	char			*share_name;
	struct path		root;		/* share root, owns a ref */
	unsigned int		root_path_sz;

	/* Serialises all journal I/O, and the recovery pass. */
	struct mutex		lock;
	struct file		*slot[KSMBD_CA_NR_SLOTS];
	unsigned int		active;
	u64			generation;
	loff_t			tail;		/* append offset in active slot */
	unsigned int		live;		/* records as of last compaction */
	unsigned int		appended;	/* records added since then */
	bool			recovered;
};

void ksmbd_ca_store_shutdown(void);

int ksmbd_ca_share_enable(struct ksmbd_work *work,
			  struct ksmbd_share_config *share);
void ksmbd_ca_share_release(struct ksmbd_share_config *share);
bool ksmbd_ca_share_ready(struct ksmbd_share_config *share);
int ksmbd_ca_veto_patterns(struct ksmbd_share_config *share,
			   int (*add)(struct ksmbd_share_config *share,
				      const char *pattern, size_t len));

struct ksmbd_ca_store *ksmbd_ca_store_get(struct ksmbd_ca_store *cas);
void ksmbd_ca_store_put(struct ksmbd_ca_store *cas);

int ksmbd_ca_record_open(struct ksmbd_file *fp);
int ksmbd_ca_record_reconnect(struct ksmbd_file *fp,
			      const struct ksmbd_user *user);
int ksmbd_ca_record_disconnect(struct ksmbd_file *fp);
void ksmbd_ca_record_close(struct ksmbd_file *fp);

#endif /* __KSMBD_CA_STORE_H__ */
