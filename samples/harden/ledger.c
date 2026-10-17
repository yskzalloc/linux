// SPDX-License-Identifier: GPL-2.0
/*
 * samples/harden/ledger.c — a deliberately buggy demo driver for the
 * "KCOV + FuzzTest" hands-on hardening tutorial (Part 4 of the book).
 *
 * Why a third driver?
 * -------------------
 * harden_local / harden_remote plant a MEMORY-SAFETY bug: an out-of-bounds
 * write that KASAN turns into a report. The fuzzer only has to reach it.
 *
 * This driver plants a LOGIC bug that no sanitizer can see: a per-open-file
 * memory QUOTA whose accounting drifts. Every access stays in bounds, every
 * allocation is freed, KASAN stays silent — and yet, after the right
 * three-call sequence, the quota check is silently disabled and the file can
 * pin more kernel memory than it was allowed to. Accounting bugs of this
 * shape (charge/uncharge imbalance, refcount drift) are a classic
 * kernel-hardening class.
 *
 * Finding it needs two things a byte-array fuzzer does not give you for free:
 *   1. a STRUCTURED, STATEFUL input — a sequence of typed calls whose handles
 *      refer to earlier results (ALLOC, then RESIZE that handle, then FREE it);
 *   2. an ORACLE that knows the right answer — a reference model of the
 *      ledger, compared after every call.
 * Both are first-class in FuzzTest (VectorOf(VariantOf(...)) domains and
 * EXPECT_* properties). See tools/harden/fuzztest/ledger_fuzztest.cc.
 *
 * ABI (one struct, four ioctls, all state is per open file):
 *   LEDGER_ALLOC   in: size          out: handle, used   (-EDQUOT, -ENOSPC)
 *   LEDGER_RESIZE  in: handle, size  out: used           (-EBADF, -EDQUOT)
 *   LEDGER_FREE    in: handle        out: used           (-EBADF)
 *   LEDGER_QUERY                     out: used
 * Invariant the driver promises: used == sum of the sizes of live objects,
 * and used <= LEDGER_QUOTA at all times.
 */

#define pr_fmt(fmt) "harden_ledger: " fmt

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define LEDGER_SLOTS	8	/* live objects per open file */
#define LEDGER_QUOTA	4096	/* bytes one open file may pin */

struct harden_ledger_op {
	__u32	handle;	/* in: RESIZE/FREE   out: ALLOC */
	__u32	size;	/* in: ALLOC/RESIZE */
	__u32	used;	/* out: bytes charged after the call */
	__u32	pad;
};

#define LEDGER_ALLOC	_IOWR('H', 0x10, struct harden_ledger_op)
#define LEDGER_RESIZE	_IOWR('H', 0x11, struct harden_ledger_op)
#define LEDGER_FREE	_IOWR('H', 0x12, struct harden_ledger_op)
#define LEDGER_QUERY	_IOR('H', 0x13, struct harden_ledger_op)

struct ledger_obj {
	void	*buf;	/* NULL = free slot */
	u32	size;	/* bytes charged for this object */
};

struct ledger {
	struct mutex		lock;
	u32			used;	/* bytes charged to this file */
	struct ledger_obj	obj[LEDGER_SLOTS];
};

/* The quota check. Written as "size > room" so it cannot overflow ... as long
 * as used <= LEDGER_QUOTA really holds. Once used drifts past the quota,
 * LEDGER_QUOTA - used wraps to a huge u32 and this check lets everything in.
 */
static bool ledger_fits(const struct ledger *l, u32 size)
{
	return size <= LEDGER_QUOTA - l->used;
}

static noinline long ledger_alloc(struct ledger *l, struct harden_ledger_op *op)
{
	unsigned int h;

	if (op->size == 0 || op->size > LEDGER_QUOTA)
		return -EINVAL;
	if (!ledger_fits(l, op->size))
		return -EDQUOT;
	for (h = 0; h < LEDGER_SLOTS; h++)
		if (!l->obj[h].buf)
			break;
	if (h == LEDGER_SLOTS)
		return -ENOSPC;

	l->obj[h].buf = kzalloc(op->size, GFP_KERNEL_ACCOUNT);
	if (!l->obj[h].buf)
		return -ENOMEM;
	l->obj[h].size = op->size;
	l->used += op->size;
	op->handle = h;
	return 0;
}

static noinline long ledger_resize(struct ledger *l, struct harden_ledger_op *op)
{
	struct ledger_obj *o;
	u32 old;
	void *nbuf;

	if (op->handle >= LEDGER_SLOTS || !l->obj[op->handle].buf)
		return -EBADF;
	if (op->size == 0 || op->size > LEDGER_QUOTA)
		return -EINVAL;

	o = &l->obj[op->handle];
	old = o->size;
	if (op->size > old && !ledger_fits(l, op->size - old))
		return -EDQUOT;

	nbuf = krealloc(o->buf, op->size, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!nbuf)
		return -ENOMEM;
	o->buf = nbuf;
	l->used = l->used - old + op->size;
	/*
	 * BUG: the ledger total was updated, but the object's own charge was
	 * not — the "o->size = op->size;" line is missing. Nothing goes out of
	 * bounds (krealloc really did resize the buffer), so KASAN is silent.
	 * The NEXT resize or free of this handle uncharges the stale size:
	 *   ALLOC 4000 -> RESIZE 100 -> FREE   leaves used = 100 - 4000,
	 * which wraps to ~4 GiB, and from then on ledger_fits() says yes to
	 * everything: the per-file quota is gone.
	 */
	return 0;
}

static noinline long ledger_free(struct ledger *l, struct harden_ledger_op *op)
{
	struct ledger_obj *o;

	if (op->handle >= LEDGER_SLOTS || !l->obj[op->handle].buf)
		return -EBADF;

	o = &l->obj[op->handle];
	kfree(o->buf);
	o->buf = NULL;
	l->used -= o->size;		/* uncharges the (possibly stale) size */
	o->size = 0;
	return 0;
}

static long ledger_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ledger *l = file->private_data;
	struct harden_ledger_op op;
	long ret;

	if (copy_from_user(&op, (void __user *)arg, sizeof(op)))
		return -EFAULT;

	mutex_lock(&l->lock);
	switch (cmd) {
	case LEDGER_ALLOC:
		ret = ledger_alloc(l, &op);
		break;
	case LEDGER_RESIZE:
		ret = ledger_resize(l, &op);
		break;
	case LEDGER_FREE:
		ret = ledger_free(l, &op);
		break;
	case LEDGER_QUERY:
		ret = 0;
		break;
	default:
		ret = -ENOTTY;
	}
	op.used = l->used;
	mutex_unlock(&l->lock);

	if (ret == 0 && copy_to_user((void __user *)arg, &op, sizeof(op)))
		ret = -EFAULT;
	return ret;
}

static int ledger_open(struct inode *inode, struct file *file)
{
	struct ledger *l = kzalloc(sizeof(*l), GFP_KERNEL);

	if (!l)
		return -ENOMEM;
	mutex_init(&l->lock);
	file->private_data = l;
	return 0;
}

static int ledger_release(struct inode *inode, struct file *file)
{
	struct ledger *l = file->private_data;
	unsigned int h;

	for (h = 0; h < LEDGER_SLOTS; h++)
		kfree(l->obj[h].buf);
	kfree(l);
	return 0;
}

static const struct file_operations ledger_fops = {
	.owner		= THIS_MODULE,
	.open		= ledger_open,
	.release	= ledger_release,
	.unlocked_ioctl	= ledger_ioctl,
};

static struct miscdevice ledger_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "harden_ledger",
	.fops	= &ledger_fops,
	.mode	= 0600,
};

static int __init ledger_init(void)
{
	int ret = misc_register(&ledger_misc);

	if (!ret)
		pr_info("loaded: /dev/harden_ledger (slots=%d, quota=%d bytes)\n",
			LEDGER_SLOTS, LEDGER_QUOTA);
	return ret;
}

static void __exit ledger_exit(void)
{
	misc_deregister(&ledger_misc);
}

module_init(ledger_init);
module_exit(ledger_exit);

MODULE_DESCRIPTION("Deliberately buggy quota-accounting demo for KCOV + FuzzTest");
MODULE_AUTHOR("hardening tutorial");
MODULE_LICENSE("GPL");
