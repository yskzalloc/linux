// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * On-disk state store and startup recovery for SMB3 persistent handles on
 * Continuously Available (CA) shares.
 *
 * MS-SMB2 requires that a persistent handle survives the loss of the server,
 * not merely the loss of the connection: after the server comes back the
 * client reconnects the handle with a DURABLE_HANDLE_RECONNECT_V2 create
 * context and expects its open to resume.  ksmbd's durable handle state is
 * memory-only, so this file adds the missing piece: a per-share, crash-safe
 * journal of every persistent open, and a recovery pass that rebuilds the
 * detached opens from it when the share is connected again.
 *
 * Layout.  Each CA share gets a <share>/.ksmbd-ca directory containing two
 * journal slots, handles.0 and handles.1.  Exactly one slot is active; the
 * other is the compaction target.  A slot is a 64-byte header followed by
 * variable-length records, appended in order, each covering one persistent
 * open.  The last record for a persistent id wins, and a record carrying
 * KSMBD_CA_F_CLOSED retires that id.
 *
 * Crash safety.  Every record carries a CRC over its own body, and the CRC is
 * seeded with the slot generation.  A torn append therefore fails its CRC and
 * terminates replay at that point, and a leftover record from an earlier
 * generation (in the tail of a reused slot) fails its CRC too, so no stale
 * open can be resurrected.  Records are fsynced before the operation that
 * produced them is reported to the client.  Compaction writes the records into
 * the inactive slot first and stamps its header with generation + 1 only after
 * those records are on stable storage, so a crash mid-compaction simply leaves
 * the old slot as the newest valid one.
 */

#include <linux/crc32.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "glob.h"
#include "ca_store.h"
#include "oplock.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_config.h"
#include "smb_common.h"

/* Refuse to replay a journal larger than this; it would mean corruption. */
#define KSMBD_CA_JNL_MAX	(8U << 20)
/* Bounds the work done by the O(n^2) replay merge below. */
#define KSMBD_CA_MAX_RECORDS	4096

static LIST_HEAD(ca_store_list);
static DEFINE_MUTEX(ca_store_list_lock);
static bool ca_store_stopped;

/* One live record during replay; @rec points into the slot image. */
struct ca_live_rec {
	struct list_head	list;
	struct ksmbd_ca_rec	*rec;
};

static int ca_compact_journal_locked(struct ksmbd_ca_store *cas);

static u32 ca_rec_crc(const struct ksmbd_ca_rec *rec, u32 len, u64 generation)
{
	/*
	 * Seed with the slot generation so a record left over from a previous
	 * generation in the tail of a compacted slot cannot validate.
	 */
	u32 crc = crc32_le((u32)generation ^ (u32)(generation >> 32),
			   &rec->len, len - offsetof(struct ksmbd_ca_rec, len));

	return crc;
}

static u32 ca_hdr_crc(const struct ksmbd_ca_hdr *hdr)
{
	return crc32_le(~0U, &hdr->version,
			sizeof(*hdr) - offsetof(struct ksmbd_ca_hdr, version));
}

static int ca_pwrite(struct file *filp, loff_t pos, const void *buf, size_t len)
{
	ssize_t n;

	n = kernel_write(filp, buf, len, &pos);
	if (n < 0)
		return n;
	if ((size_t)n != len)
		return -EIO;
	return 0;
}

static int ca_pread(struct file *filp, loff_t pos, void *buf, size_t len)
{
	ssize_t n;

	n = kernel_read(filp, buf, len, &pos);
	if (n < 0)
		return n;
	if ((size_t)n != len)
		return -EIO;
	return 0;
}

/*
 * Create the state directory relative to the share root.  This mirrors
 * ksmbd_vfs_kern_path_create() but takes the share directly, because the
 * store is set up from TREE_CONNECT where work->tcon is not yet published.
 */
static int ca_mkdir(struct ksmbd_share_config *share)
{
	struct path path;
	struct dentry *dent;
	struct qstr last;
	int err;

	CLASS(filename_kernel, filename)(KSMBD_CA_DIR);

	err = vfs_path_parent_lookup(filename, LOOKUP_NO_SYMLINKS |
				     LOOKUP_DIRECTORY | LOOKUP_BENEATH,
				     &path, &last, &share->vfs_path);
	if (err)
		return err;

	err = mnt_want_write(path.mnt);
	if (err) {
		path_put(&path);
		return err;
	}

	dent = start_creating_noperm(path.dentry, &last);
	if (IS_ERR(dent)) {
		err = PTR_ERR(dent);
		mnt_drop_write(path.mnt);
		path_put(&path);
		return err == -EEXIST ? 0 : err;
	}

	dent = vfs_mkdir(mnt_idmap(path.mnt), d_inode(path.dentry), dent,
			 S_IFDIR | 0700, NULL);
	if (IS_ERR(dent))
		err = PTR_ERR(dent);
	else if (d_is_negative(dent))
		err = -ENOENT;

	end_creating_path(&path, dent);
	if (err == -EEXIST)
		err = 0;
	return err;
}

static struct file *ca_slot_open(struct ksmbd_share_config *share,
				 unsigned int idx)
{
	char name[sizeof(KSMBD_CA_DIR) + 16];

	scnprintf(name, sizeof(name), "%s/handles.%u", KSMBD_CA_DIR, idx);
	return file_open_root(&share->vfs_path, name,
			      O_RDWR | O_CREAT | O_LARGEFILE | O_NOFOLLOW,
			      0600);
}

/* Read a slot header; returns true and fills @hdr when it is valid. */
static bool ca_hdr_load(struct file *filp, struct ksmbd_ca_hdr *hdr)
{
	if (ca_pread(filp, 0, hdr, sizeof(*hdr)))
		return false;
	if (le32_to_cpu(hdr->magic) != KSMBD_CA_HDR_MAGIC)
		return false;
	if (le32_to_cpu(hdr->crc) != ca_hdr_crc(hdr))
		return false;
	if (le16_to_cpu(hdr->version) != KSMBD_CA_VERSION)
		return false;
	if (le16_to_cpu(hdr->hdr_size) != KSMBD_CA_HDR_SIZE)
		return false;
	return true;
}

static int ca_hdr_store(struct file *filp, u64 generation, u64 nr_records)
{
	struct ksmbd_ca_hdr hdr = {};
	int ret;

	BUILD_BUG_ON(sizeof(hdr) != KSMBD_CA_HDR_SIZE);

	hdr.magic = cpu_to_le32(KSMBD_CA_HDR_MAGIC);
	hdr.version = cpu_to_le16(KSMBD_CA_VERSION);
	hdr.hdr_size = cpu_to_le16(KSMBD_CA_HDR_SIZE);
	hdr.generation = cpu_to_le64(generation);
	hdr.nr_records = cpu_to_le64(nr_records);
	hdr.crc = cpu_to_le32(ca_hdr_crc(&hdr));

	ret = ca_pwrite(filp, 0, &hdr, sizeof(hdr));
	if (ret)
		return ret;
	return vfs_fsync(filp, 0);
}

/*
 * Zero the record header at @pos.  A zeroed magic stops replay, which makes
 * the end of the journal explicit instead of relying on a stale tail from an
 * earlier generation failing its CRC.
 */
static int ca_terminate(struct file *filp, loff_t pos)
{
	static const u8 zero[KSMBD_CA_TERM_SIZE];

	return ca_pwrite(filp, pos, zero, sizeof(zero));
}

static void ca_store_free(struct ksmbd_ca_store *cas)
{
	unsigned int i;

	for (i = 0; i < KSMBD_CA_NR_SLOTS; i++)
		if (cas->slot[i])
			fput(cas->slot[i]);
	if (cas->root.dentry)
		path_put(&cas->root);
	kfree(cas->share_name);
	mutex_destroy(&cas->lock);
	kfree(cas);
}

/*
 * Called by kref_put_mutex() with ca_store_list_lock held, and must release it.
 * Unlinking here, under the same lock the lookup below takes, is what makes
 * ca_store_tryget() safe: a lookup either observes a live store, or observes
 * one whose count has already reached zero and rejects it.
 */
static void ca_store_release(struct kref *kref)
{
	struct ksmbd_ca_store *cas =
		container_of(kref, struct ksmbd_ca_store, kref);

	list_del_init(&cas->list);
	mutex_unlock(&ca_store_list_lock);
	ca_store_free(cas);
}

/* Take a reference the caller does not already hold.  NULL if it is dying. */
static struct ksmbd_ca_store *ca_store_tryget(struct ksmbd_ca_store *cas)
{
	if (cas && kref_get_unless_zero(&cas->kref))
		return cas;
	return NULL;
}

/* Take another reference on a store the caller already holds one on. */
struct ksmbd_ca_store *ksmbd_ca_store_get(struct ksmbd_ca_store *cas)
{
	if (cas)
		kref_get(&cas->kref);
	return cas;
}

void ksmbd_ca_store_put(struct ksmbd_ca_store *cas)
{
	if (cas)
		kref_put_mutex(&cas->kref, ca_store_release,
			       &ca_store_list_lock);
}

/*
 * Replay the active slot into a list of live records, newest wins.  @image
 * holds the slot contents and outlives the returned list.
 */
static int ca_replay(struct ksmbd_ca_store *cas, void *image, size_t len,
		     struct list_head *live, unsigned int *nr_stale)
{
	size_t off = KSMBD_CA_HDR_SIZE;
	unsigned int nr = 0;

	*nr_stale = 0;

	while (off + sizeof(struct ksmbd_ca_rec) <= len) {
		struct ksmbd_ca_rec *rec = image + off;
		struct ca_live_rec *cur, *found = NULL;
		u32 reclen;

		if (le32_to_cpu(rec->magic) != KSMBD_CA_REC_MAGIC)
			break;

		reclen = le32_to_cpu(rec->len);
		if (reclen < sizeof(*rec) || reclen > KSMBD_CA_REC_MAX ||
		    (reclen & 7) || off + reclen > len)
			break;

		if (le32_to_cpu(rec->crc) !=
		    ca_rec_crc(rec, reclen, cas->generation))
			break;

		if ((size_t)le16_to_cpu(rec->name_len) +
		    le16_to_cpu(rec->owner_len) > reclen - sizeof(*rec))
			break;

		off += reclen;

		if (++nr > KSMBD_CA_MAX_RECORDS) {
			pr_warn("CA journal for '%s' exceeds %u records\n",
				cas->share_name, KSMBD_CA_MAX_RECORDS);
			return -EFBIG;
		}

		list_for_each_entry(cur, live, list) {
			if (cur->rec->persistent_id == rec->persistent_id) {
				found = cur;
				break;
			}
		}

		if (le32_to_cpu(rec->flags) & KSMBD_CA_F_CLOSED) {
			if (found) {
				list_del(&found->list);
				kfree(found);
			}
			(*nr_stale)++;
			continue;
		}

		if (found) {
			/* Superseded by this newer record. */
			found->rec = rec;
			(*nr_stale)++;
			continue;
		}

		cur = kzalloc_obj(struct ca_live_rec, KSMBD_DEFAULT_GFP);
		if (!cur)
			return -ENOMEM;
		cur->rec = rec;
		list_add_tail(&cur->list, live);
	}

	return 0;
}

static void ca_live_free(struct list_head *live)
{
	struct ca_live_rec *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, live, list) {
		list_del(&cur->list);
		kfree(cur);
	}
}

/*
 * Write @live into the inactive slot under a new generation and switch over.
 * Called with cas->lock held.
 */
static int ca_compact_locked(struct ksmbd_ca_store *cas, struct list_head *live)
{
	unsigned int target = cas->active ^ 1;
	struct file *filp = cas->slot[target];
	u64 generation = cas->generation + 1;
	struct ca_live_rec *cur;
	loff_t pos = KSMBD_CA_HDR_SIZE;
	u64 nr = 0;
	int ret;

	list_for_each_entry(cur, live, list) {
		struct ksmbd_ca_rec *rec = cur->rec;
		u32 reclen = le32_to_cpu(rec->len);

		rec->crc = cpu_to_le32(ca_rec_crc(rec, reclen, generation));
		ret = ca_pwrite(filp, pos, rec, reclen);
		if (ret)
			return ret;
		pos += reclen;
		nr++;
	}

	ret = ca_terminate(filp, pos);
	if (ret)
		return ret;

	ret = vfs_fsync(filp, 0);
	if (ret)
		return ret;

	/*
	 * Only now is the new slot complete on stable storage; stamping the
	 * header publishes it.  A crash before this point leaves the old slot
	 * as the newest valid generation.
	 */
	ret = ca_hdr_store(filp, generation, nr);
	if (ret)
		return ret;

	cas->active = target;
	cas->generation = generation;
	cas->tail = pos;
	cas->live = nr;
	cas->appended = 0;
	return 0;
}

static int ca_append_locked(struct ksmbd_ca_store *cas,
			    struct ksmbd_ca_rec *rec)
{
	struct file *filp = cas->slot[cas->active];
	u32 reclen = le32_to_cpu(rec->len);
	int ret;

	rec->magic = cpu_to_le32(KSMBD_CA_REC_MAGIC);
	rec->crc = cpu_to_le32(ca_rec_crc(rec, reclen, cas->generation));

	/*
	 * ca_rec_build() overallocates by KSMBD_CA_TERM_SIZE zeroed bytes so
	 * the record and the terminator that follows it go out as one write.
	 * A torn write then either leaves a record that fails its CRC, or a
	 * complete record that is already terminated; it can never leave a
	 * valid record whose end is ambiguous.
	 */
	ret = ca_pwrite(filp, cas->tail, rec, reclen + KSMBD_CA_TERM_SIZE);
	if (ret)
		return ret;

	ret = vfs_fsync(filp, 0);
	if (ret)
		return ret;

	cas->tail += reclen;
	cas->appended++;
	return 0;
}

/*
 * Build a record for @fp.  Returns a kvmalloc'd record the caller frees.
 * @name is the share-relative path of the open.
 */
static struct ksmbd_ca_rec *ca_rec_build(struct ksmbd_ca_store *cas,
					 struct ksmbd_file *fp,
					 const struct ksmbd_user *user,
					 const char *name, u32 flags)
{
	struct ksmbd_ca_rec *rec;
	struct oplock_info *opinfo;
	size_t name_len, owner_len, reclen;
	char owner[KSMBD_REQ_MAX_ACCOUNT_NAME_SZ] = "";
	unsigned int uid, gid;
	u8 *p;

	name_len = strlen(name);
	if (name_len > PATH_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	/*
	 * An alternate data stream has no path of its own to recover from, so
	 * persistent handles are not granted on streams (see smb2_open()); this
	 * only guards against that changing.
	 */
	if (WARN_ON_ONCE(ksmbd_stream_fd(fp)))
		return ERR_PTR(-EOPNOTSUPP);

	/*
	 * ksmbd_reopen_durable_fd() clears the stored owner, so a reconnect
	 * passes the reconnecting identity explicitly: the journal must always
	 * describe who may reconnect this handle next, including after a crash
	 * that happens while the handle is connected.
	 *
	 * The name is copied into a fixed buffer rather than duplicated,
	 * because fp->f_lock is a spinlock.
	 */
	if (user) {
		strscpy(owner, user->name, sizeof(owner));
		uid = user->uid;
		gid = user->gid;
		flags |= KSMBD_CA_F_OWNER;
	} else {
		spin_lock(&fp->f_lock);
		if (fp->owner.name) {
			strscpy(owner, fp->owner.name, sizeof(owner));
			flags |= KSMBD_CA_F_OWNER;
		}
		uid = fp->owner.uid;
		gid = fp->owner.gid;
		spin_unlock(&fp->f_lock);
	}
	owner_len = strlen(owner);

	reclen = ALIGN(sizeof(*rec) + name_len + owner_len, 8);
	if (reclen > KSMBD_CA_REC_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	/* Trailing zeroes double as the journal terminator; see ca_append_locked(). */
	rec = kvzalloc(reclen + KSMBD_CA_TERM_SIZE, KSMBD_DEFAULT_GFP);
	if (!rec)
		return ERR_PTR(-ENOMEM);

	rec->len = cpu_to_le32(reclen);
	rec->persistent_id = cpu_to_le64(fp->persistent_id);
	/*
	 * A connected handle records its live volatile id; once disconnected
	 * the id has moved to durable_volatile_id, which is what DH2C and
	 * DHnC validate against.
	 */
	rec->volatile_id = cpu_to_le64(has_file_id(fp->volatile_id) ?
				       fp->volatile_id : fp->durable_volatile_id);

	memcpy(rec->create_guid, fp->create_guid, sizeof(rec->create_guid));
	memcpy(rec->client_guid, fp->client_guid, sizeof(rec->client_guid));
	memcpy(rec->app_instance_id, fp->app_instance_id,
	       sizeof(rec->app_instance_id));

	rec->daccess = fp->daccess;
	rec->saccess = fp->saccess;
	rec->coption = fp->coption;
	rec->cdoption = fp->cdoption;
	rec->file_attributes = fp->create_file_attributes;
	rec->create_action = fp->create_action;

	rec->create_time = cpu_to_le64(fp->create_time);
	rec->change_time = cpu_to_le64(fp->change_time);
	rec->itime = cpu_to_le64(fp->itime);
	rec->allocation_size = cpu_to_le64(fp->allocation_size);

	rec->durable_timeout = cpu_to_le32(fp->durable_timeout);
	rec->uid = cpu_to_le32(uid);
	rec->gid = cpu_to_le32(gid);

	if (fp->durable_replay_consumed)
		flags |= KSMBD_CA_F_REPLAY_CONSUMED;
	if (fp->filp && S_ISDIR(file_inode(fp->filp)->i_mode))
		flags |= KSMBD_CA_F_DIR;

	/*
	 * MS-SMB2 3.3.5.9.10: the handle must come back with the same
	 * oplock/lease it was granted, otherwise the client's cached state is
	 * silently wrong after failover.
	 */
	opinfo = opinfo_get(fp);
	if (opinfo) {
		rec->oplock_level = cpu_to_le32(opinfo->level);
		if (opinfo->is_lease && opinfo->o_lease) {
			struct lease *lease = opinfo->o_lease;

			flags |= KSMBD_CA_F_LEASE;
			rec->lease_state = lease->state;
			rec->lease_flags = lease->flags;
			rec->lease_duration = lease->duration;
			rec->lease_epoch = cpu_to_le16(lease->epoch);
			rec->lease_version = cpu_to_le16(lease->version);
			memcpy(rec->lease_key, lease->lease_key,
			       sizeof(rec->lease_key));
			memcpy(rec->parent_lease_key, lease->parent_lease_key,
			       sizeof(rec->parent_lease_key));
		}
		opinfo_put(opinfo);
	}

	if (flags & KSMBD_CA_F_DISCONNECTED && fp->durable_timeout)
		rec->expires_at = cpu_to_le64(ktime_get_real_seconds() +
					      fp->durable_timeout / MSEC_PER_SEC);

	rec->flags = cpu_to_le32(flags);
	rec->name_len = cpu_to_le16(name_len);
	rec->owner_len = cpu_to_le16(owner_len);

	p = rec->payload;
	memcpy(p, name, name_len);
	p += name_len;
	if (owner_len)
		memcpy(p, owner, owner_len);

	return rec;
}

/*
 * Share-relative path of @fp's open, as stored in the journal and as used to
 * re-open the file during recovery.  Derived from the dentry so a rename of an
 * open persistent handle is recorded correctly.
 */
static char *ca_fp_name(struct ksmbd_ca_store *cas, struct ksmbd_file *fp)
{
	char *buf, *abs, *name;

	if (!fp->filp)
		return ERR_PTR(-EBADF);

	buf = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	abs = d_path(&fp->filp->f_path, buf, PATH_MAX);
	if (IS_ERR(abs)) {
		kfree(buf);
		return ERR_CAST(abs);
	}

	if (strlen(abs) <= cas->root_path_sz + 1) {
		kfree(buf);
		return ERR_PTR(-EINVAL);
	}

	name = kstrdup(abs + cas->root_path_sz + 1, KSMBD_DEFAULT_GFP);
	kfree(buf);
	return name ? name : ERR_PTR(-ENOMEM);
}

static int ca_record(struct ksmbd_file *fp,
		     const struct ksmbd_user *user, u32 flags)
{
	struct ksmbd_ca_store *cas = fp->ca_store;
	struct ksmbd_ca_rec *rec;
	char *name;
	int ret;

	if (!cas || ca_store_stopped)
		return 0;

	name = ca_fp_name(cas, fp);
	if (IS_ERR(name))
		return PTR_ERR(name);

	rec = ca_rec_build(cas, fp, user, name, flags);
	kfree(name);
	if (IS_ERR(rec))
		return PTR_ERR(rec);

	mutex_lock(&cas->lock);
	ret = ca_append_locked(cas, rec);
	/*
	 * Updates and tombstones pile up; fold the journal down once they
	 * dominate the live set, which keeps the cost amortised while bounding
	 * both the file size and the work replay has to do.
	 */
	if (!ret && cas->appended > KSMBD_CA_COMPACT_MIN &&
	    cas->appended > 2 * cas->live)
		ca_compact_journal_locked(cas);
	mutex_unlock(&cas->lock);

	kvfree(rec);
	return ret;
}

int ksmbd_ca_record_open(struct ksmbd_file *fp)
{
	return ca_record(fp, NULL, 0);
}

int ksmbd_ca_record_reconnect(struct ksmbd_file *fp,
			      const struct ksmbd_user *user)
{
	/*
	 * Clear the disconnected state and its deadline: the handle is live
	 * again, and if the server dies now the client must get the full
	 * durable timeout to come back, not the remainder of the old one.
	 */
	return ca_record(fp, user, 0);
}

int ksmbd_ca_record_disconnect(struct ksmbd_file *fp)
{
	return ca_record(fp, NULL, KSMBD_CA_F_DISCONNECTED);
}

void ksmbd_ca_record_close(struct ksmbd_file *fp)
{
	struct ksmbd_ca_store *cas = fp->ca_store;
	int ret;

	if (!cas)
		return;

	/*
	 * Module teardown closes every handle in the global table.  Those
	 * opens are exactly the ones a persistent handle is supposed to
	 * survive, so do not tombstone them.
	 */
	if (!ca_store_stopped) {
		ret = ca_record(fp, NULL, KSMBD_CA_F_CLOSED);
		if (ret)
			pr_warn("CA journal tombstone failed for '%s': %d\n",
				cas->share_name, ret);
	}

	fp->ca_store = NULL;
	ksmbd_ca_store_put(cas);
}

/* Rebuild one detached persistent open from @rec. */
static int ca_recover_one(struct ksmbd_ca_store *cas, struct ksmbd_ca_rec *rec)
{
	struct ksmbd_durable_recovery r = {};
	struct lease_ctx_info lctx = {};
	struct ksmbd_file *fp;
	struct file *filp;
	char *name, *owner = NULL;
	u32 flags = le32_to_cpu(rec->flags);
	u16 name_len = le16_to_cpu(rec->name_len);
	u16 owner_len = le16_to_cpu(rec->owner_len);
	u64 expires_at = le64_to_cpu(rec->expires_at);
	int open_flags, ret;

	/*
	 * A handle whose durable timeout ran out while the server was down is
	 * not recoverable; drop it so the next compaction forgets it.
	 */
	if (expires_at && expires_at <= (u64)ktime_get_real_seconds())
		return -ETIMEDOUT;

	name = kmemdup_nul(rec->payload, name_len, KSMBD_DEFAULT_GFP);
	if (!name)
		return -ENOMEM;
	/*
	 * Restore the identity whenever the record says it has one, even if the
	 * name is empty: ksmbd_vfs_compare_durable_owner() treats a NULL name
	 * as "unknown owner" and refuses the reconnect outright.
	 */
	if (flags & KSMBD_CA_F_OWNER) {
		owner = kmemdup_nul(rec->payload + name_len, owner_len,
				    KSMBD_DEFAULT_GFP);
		if (!owner) {
			kfree(name);
			return -ENOMEM;
		}
	}

	/*
	 * The exact open flags of the original CREATE are not journalled; they
	 * are re-derived from the recorded DesiredAccess.  O_SYNC is
	 * unconditional because every open on a CA share is write-through.
	 */
	if (flags & KSMBD_CA_F_DIR) {
		open_flags = O_RDONLY | O_DIRECTORY;
	} else {
		open_flags = O_LARGEFILE | O_SYNC;
		if (le32_to_cpu(rec->daccess) &
		    (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
		     FILE_WRITE_ATTRIBUTES))
			open_flags |= O_RDWR;
		else
			open_flags |= O_RDONLY;
	}

	/*
	 * file_open_root() resolves @name with the share root as the lookup
	 * root, so a tampered journal cannot name a path outside the share:
	 * ".." at the root stays at the root and a leading '/' is relative to
	 * it.  O_NOFOLLOW additionally refuses a final component that has been
	 * replaced by a symlink while the server was down.
	 */
	filp = file_open_root(&cas->root, name, open_flags | O_NOFOLLOW, 0);
	if (IS_ERR(filp) && (open_flags & O_RDWR)) {
		/* The file may have lost write permission while we were down. */
		open_flags = (open_flags & ~O_RDWR) | O_RDONLY;
		filp = file_open_root(&cas->root, name,
				      open_flags | O_NOFOLLOW, 0);
	}
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		ksmbd_debug(SMB, "CA recovery: cannot open '%s': %d\n",
			    name, ret);
		goto out;
	}

	ksmbd_vfs_set_fadvise(filp, rec->coption | FILE_WRITE_THROUGH_LE);

	r.persistent_id = le64_to_cpu(rec->persistent_id);
	r.volatile_id = le64_to_cpu(rec->volatile_id);
	r.daccess = rec->daccess;
	r.saccess = rec->saccess;
	r.coption = rec->coption;
	r.cdoption = rec->cdoption;
	r.create_file_attributes = rec->file_attributes;
	r.create_action = rec->create_action;
	r.create_time = le64_to_cpu(rec->create_time);
	r.change_time = le64_to_cpu(rec->change_time);
	r.itime = le64_to_cpu(rec->itime);
	r.allocation_size = le64_to_cpu(rec->allocation_size);
	r.durable_timeout = le32_to_cpu(rec->durable_timeout);
	/*
	 * The scavenger deadline is kept in jiffies-derived milliseconds,
	 * which restart at zero, so rearm it from the wall-clock deadline that
	 * was journalled.
	 */
	if (expires_at)
		r.remaining_ms = (unsigned int)min_t(u64, U32_MAX / 2,
			(expires_at - (u64)ktime_get_real_seconds()) *
			MSEC_PER_SEC);
	else
		r.remaining_ms = r.durable_timeout;
	memcpy(r.create_guid, rec->create_guid, sizeof(r.create_guid));
	memcpy(r.client_guid, rec->client_guid, sizeof(r.client_guid));
	memcpy(r.app_instance_id, rec->app_instance_id,
	       sizeof(r.app_instance_id));
	r.uid = le32_to_cpu(rec->uid);
	r.gid = le32_to_cpu(rec->gid);
	r.owner_name = owner;
	r.replay_consumed = !!(flags & KSMBD_CA_F_REPLAY_CONSUMED);
	r.oplock_level = le32_to_cpu(rec->oplock_level);
	r.is_lease = !!(flags & KSMBD_CA_F_LEASE);

	if (r.is_lease) {
		memcpy(lctx.lease_key, rec->lease_key, sizeof(lctx.lease_key));
		memcpy(lctx.parent_lease_key, rec->parent_lease_key,
		       sizeof(lctx.parent_lease_key));
		lctx.req_state = rec->lease_state;
		lctx.flags = rec->lease_flags;
		lctx.duration = rec->lease_duration;
		lctx.epoch = rec->lease_epoch;
		lctx.version = le16_to_cpu(rec->lease_version);
		lctx.is_dir = !!(flags & KSMBD_CA_F_DIR);
		r.lctx = &lctx;
	}

	fp = ksmbd_recover_durable_fd(filp, cas, &r);
	if (IS_ERR(fp)) {
		ret = PTR_ERR(fp);
		fput(filp);
		goto out;
	}

	ret = 0;
out:
	kfree(owner);
	kfree(name);
	return ret;
}

/*
 * Replay the active slot, then rebuild every live open it describes, then
 * compact so the journal only lists what actually came back.
 *
 * Failures are deliberately asymmetric.  A replay failure means the journal
 * cannot be understood, and is reported so the share refuses to claim CA.
 * Once opens have been rebuilt, however, they hold references to this store,
 * so nothing after that point may tear it down: an individual open that
 * cannot be restored is simply dropped, and a failed compaction only leaves a
 * longer journal behind.
 *
 * Called with cas->lock held.
 */
/*
 * Read the active slot and hand back the set of live records, newest wins.
 * @image must be kvfree()d once the returned list is no longer used, since the
 * records point into it.  Called with cas->lock held.
 */
static int ca_load_live_locked(struct ksmbd_ca_store *cas, void **image,
			       struct list_head *live, unsigned int *nr_stale)
{
	struct file *filp = cas->slot[cas->active];
	loff_t size;
	void *buf;
	int ret;

	*image = NULL;
	*nr_stale = 0;

	size = i_size_read(file_inode(filp));
	if (size > KSMBD_CA_JNL_MAX) {
		pr_err("CA journal for '%s' is %lld bytes, refusing\n",
		       cas->share_name, size);
		return -EFBIG;
	}
	if (size <= KSMBD_CA_HDR_SIZE)
		return 0;

	buf = kvzalloc(size, KSMBD_DEFAULT_GFP);
	if (!buf)
		return -ENOMEM;

	ret = ca_pread(filp, 0, buf, size);
	if (!ret)
		ret = ca_replay(cas, buf, size, live, nr_stale);
	if (ret) {
		ca_live_free(live);
		kvfree(buf);
		return ret;
	}

	*image = buf;
	return 0;
}

/*
 * Fold the journal down to its live records.  Called with cas->lock held.
 */
static int ca_compact_journal_locked(struct ksmbd_ca_store *cas)
{
	LIST_HEAD(live);
	unsigned int stale;
	void *image;
	int ret;

	ret = ca_load_live_locked(cas, &image, &live, &stale);
	if (ret)
		return ret;

	ret = ca_compact_locked(cas, &live);
	ca_live_free(&live);
	kvfree(image);
	return ret;
}

static int ca_recover_locked(struct ksmbd_ca_store *cas)
{
	struct ca_live_rec *cur, *tmp;
	LIST_HEAD(live);
	unsigned int stale = 0, recovered = 0, dropped = 0;
	void *image;
	int ret;

	cas->tail = KSMBD_CA_HDR_SIZE;

	ret = ca_load_live_locked(cas, &image, &live, &stale);
	if (ret)
		return ret;

	/*
	 * Past this point the store must survive: the opens rebuilt below take
	 * references to it, so no caller may tear it down on error.  An open
	 * that cannot be restored is dropped, and a failed compaction only
	 * leaves a longer journal behind.
	 */
	list_for_each_entry_safe(cur, tmp, &live, list) {
		if (ca_recover_one(cas, cur->rec)) {
			list_del(&cur->list);
			kfree(cur);
			dropped++;
			continue;
		}
		recovered++;
	}

	if (ca_compact_locked(cas, &live))
		pr_warn("CA journal compaction failed for '%s'\n",
			cas->share_name);

	if (recovered || dropped || stale)
		pr_info("CA share '%s': recovered %u persistent handle(s), dropped %u, reclaimed %u stale record(s)\n",
			cas->share_name, recovered, dropped, stale);

	ca_live_free(&live);
	kvfree(image);
	cas->recovered = true;
	return 0;
}

/*
 * Open (or create) the journal slots and pick the newest valid one.  Recovery
 * is deliberately *not* done here: it runs later, under cas->lock, once this
 * store is known to be the one published for the share.
 */
static struct ksmbd_ca_store *ca_store_create(struct ksmbd_share_config *share)
{
	struct ksmbd_ca_store *cas;
	struct ksmbd_ca_hdr hdr;
	u64 best = 0;
	unsigned int i;
	int ret;

	ret = ca_mkdir(share);
	if (ret) {
		pr_err("cannot create %s in share '%s': %d\n",
		       KSMBD_CA_DIR, share->name, ret);
		return ERR_PTR(ret);
	}

	cas = kzalloc_obj(struct ksmbd_ca_store, KSMBD_DEFAULT_GFP);
	if (!cas)
		return ERR_PTR(-ENOMEM);

	kref_init(&cas->kref);
	INIT_LIST_HEAD(&cas->list);
	mutex_init(&cas->lock);
	cas->root_path_sz = share->path_sz;
	cas->tail = KSMBD_CA_HDR_SIZE;
	cas->share_name = kstrdup(share->name, KSMBD_DEFAULT_GFP);
	if (!cas->share_name) {
		ret = -ENOMEM;
		goto err;
	}
	cas->root = share->vfs_path;
	path_get(&cas->root);

	for (i = 0; i < KSMBD_CA_NR_SLOTS; i++) {
		struct file *filp = ca_slot_open(share, i);

		if (IS_ERR(filp)) {
			ret = PTR_ERR(filp);
			pr_err("cannot open CA journal slot %u of share '%s': %d\n",
			       i, share->name, ret);
			goto err;
		}
		cas->slot[i] = filp;
	}

	/* The newest valid header wins; an invalid slot is simply not chosen. */
	for (i = 0; i < KSMBD_CA_NR_SLOTS; i++) {
		if (!ca_hdr_load(cas->slot[i], &hdr))
			continue;
		if (le64_to_cpu(hdr.generation) >= best) {
			best = le64_to_cpu(hdr.generation);
			cas->active = i;
			cas->generation = best;
		}
	}

	if (!best) {
		cas->active = 0;
		cas->generation = 1;
	}

	return cas;
err:
	ca_store_free(cas);
	return ERR_PTR(ret);
}

/*
 * Bring the store to a usable state.  Serialised on cas->lock, so a second
 * tree connect racing in blocks here until the first has finished recovering.
 */
static int ca_store_prepare(struct ksmbd_ca_store *cas)
{
	int ret = 0;

	mutex_lock(&cas->lock);
	if (!cas->recovered) {
		if (cas->generation == 1 &&
		    i_size_read(file_inode(cas->slot[cas->active])) == 0) {
			/* Fresh store: just stamp the first generation. */
			ret = ca_hdr_store(cas->slot[cas->active], 1, 0);
			if (!ret)
				cas->recovered = true;
		} else {
			ret = ca_recover_locked(cas);
		}
	}
	mutex_unlock(&cas->lock);
	return ret;
}

/* Caller must hold ca_store_list_lock. */
static struct ksmbd_ca_store *ca_store_lookup(const char *name)
{
	struct ksmbd_ca_store *cas;

	list_for_each_entry(cas, &ca_store_list, list)
		if (!strcmp(cas->share_name, name))
			return cas;
	return NULL;
}

int ksmbd_ca_share_enable(struct ksmbd_work *work,
			  struct ksmbd_share_config *share)
{
	struct ksmbd_ca_store *cas = NULL, *found;
	int ret;

	if (!test_share_config_flag(share,
				    KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY))
		return 0;
	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE) || !share->path)
		return -EINVAL;
	if (ca_store_stopped)
		return -ESHUTDOWN;
	if (share->ca_store)
		return 0;

	/*
	 * A share config can be torn down and re-instantiated (on reload, or
	 * when its last tree connect goes away) while persistent handles it
	 * created are still disconnected.  Reuse the existing store in that
	 * case so those handles keep the journal they were recorded in.
	 */
	mutex_lock(&ca_store_list_lock);
	if (share->ca_store) {
		mutex_unlock(&ca_store_list_lock);
		return 0;
	}
	found = ca_store_tryget(ca_store_lookup(share->name));
	mutex_unlock(&ca_store_list_lock);

	/*
	 * All journal and recovery I/O runs as the share's forced identity, so
	 * reopening a recovered file is subject to the same checks the original
	 * CREATE was.
	 */
	ret = __ksmbd_override_fsids(work, share);
	if (ret) {
		ksmbd_ca_store_put(found);
		return ret;
	}

	if (!found) {
		cas = ca_store_create(share);
		if (IS_ERR(cas)) {
			ksmbd_revert_fsids(work);
			return PTR_ERR(cas);
		}

		mutex_lock(&ca_store_list_lock);
		found = ca_store_tryget(ca_store_lookup(share->name));
		if (!found) {
			/*
			 * The list keeps its own reference for as long as the
			 * module is loaded.  A share config can come and go
			 * (its last tree connect disconnecting is enough), and
			 * a second store opening the same journal files behind
			 * the back of the first would corrupt them: each keeps
			 * its own generation counter and append offset.
			 */
			list_add(&cas->list, &ca_store_list);
			found = ksmbd_ca_store_get(cas);
			cas = NULL;
		}
		mutex_unlock(&ca_store_list_lock);

		/* Lost the race; nothing references our store yet. */
		if (cas)
			ca_store_free(cas);
	}

	/*
	 * Recovery must not hold ca_store_list_lock: it publishes opens that
	 * take a reference on the store, and dropping such a reference takes
	 * that same lock.  Serialising on cas->lock is enough -- a second tree
	 * connect that found the same store blocks here until recovery is done.
	 */
	ret = ca_store_prepare(found);
	ksmbd_revert_fsids(work);
	if (ret) {
		ksmbd_ca_store_put(found);
		return ret;
	}

	/*
	 * Two tree connects can get this far concurrently; only one may publish
	 * the store on the share, or the loser's reference would be leaked.
	 */
	mutex_lock(&ca_store_list_lock);
	if (share->ca_store) {
		cas = found;
		found = NULL;
	} else {
		share->ca_store = found;
	}
	mutex_unlock(&ca_store_list_lock);

	if (cas)
		ksmbd_ca_store_put(cas);
	return 0;
}

void ksmbd_ca_share_release(struct ksmbd_share_config *share)
{
	struct ksmbd_ca_store *cas = share->ca_store;

	if (!cas)
		return;
	share->ca_store = NULL;
	ksmbd_ca_store_put(cas);
}

bool ksmbd_ca_share_ready(struct ksmbd_share_config *share)
{
	return share && share->ca_store;
}

int ksmbd_ca_veto_patterns(struct ksmbd_share_config *share,
			   int (*add)(struct ksmbd_share_config *share,
				      const char *pattern, size_t len))
{
	static const char * const pattern[] = {
		KSMBD_CA_DIR, KSMBD_CA_DIR "/*",
	};
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(pattern); i++) {
		ret = add(share, pattern[i], strlen(pattern[i]));
		if (ret)
			return ret;
	}
	return 0;
}

void ksmbd_ca_store_shutdown(void)
{
	struct ksmbd_ca_store *cas;

	/*
	 * Stop journalling before the global file table is torn down: the
	 * handles closed there are the ones that must survive a restart.
	 */
	ca_store_stopped = true;

	/*
	 * Drop the list's reference on every store.  A store still referenced
	 * by a persistent open survives until ksmbd_free_global_file_table()
	 * closes that open, which is the caller's very next step.
	 */
	for (;;) {
		mutex_lock(&ca_store_list_lock);
		cas = list_first_entry_or_null(&ca_store_list,
					       struct ksmbd_ca_store, list);
		if (cas)
			list_del_init(&cas->list);
		mutex_unlock(&ca_store_list_lock);

		if (!cas)
			break;
		ksmbd_ca_store_put(cas);
	}
}
