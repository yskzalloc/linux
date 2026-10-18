// SPDX-License-Identifier: GPL-2.0
/*
 * pointee_access_c.c - Verify that, with CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS,
 * kcov_dataflow records the values a function loads and stores through its
 * plain C pointer arguments -- one ACCESS record per access that executed, in
 * execution order, with the value the program itself loaded or stored -- and
 * nothing for the accesses it does not make, cannot see, or must not touch.
 *
 * Every function is noinline and takes the object by pointer, which C gives
 * no dereferenceable contract: there is no pointee snapshot here, only the
 * accesses. Write to /sys/kernel/debug/kcov_dataflow_test/trigger_access to
 * run it; test_modules.py knows the values each access sees.
 */
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/container_of.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KCOV dataflow pointee access test");

struct pa_inner {
	u32 x;
	u16 y;
};

struct pa_state {
	u64 id;
	struct pa_inner in;
	u8 tag[4];
	spinlock_t lock;
	atomic_t refs;
	unsigned int flag : 3, mode : 5;
};

struct pa_item {
	u64 key;
	struct list_head link;
};

/*
 * Exported, with prototypes, so that the compiler keeps every function's
 * signature as written: an internal function could have its pointer
 * arguments promoted to the values loaded through them.
 */
u64 pa_get(struct pa_state *s);
void pa_set_tag(struct pa_state *s, u8 v);
u64 pa_maybe(struct pa_state *s, int c);
void pa_twice(struct pa_state *p);
u64 pa_bump(struct pa_state *s);
u32 pa_locked(struct pa_state *s);
u64 pa_key(struct list_head *l);
u64 pa_once(struct pa_state *s);
unsigned int pa_bits(struct pa_state *s);
u64 pa_wide(unsigned __int128 *p);
u64 pa_depth(struct pa_state *s, int n);

/* Two members by plain loads: x at offset 8, y at 12. */
noinline u64 pa_get(struct pa_state *s)
{
	return s->in.x + s->in.y;
}
EXPORT_SYMBOL(pa_get);

/* A store, of an array element. */
noinline void pa_set_tag(struct pa_state *s, u8 v)
{
	s->tag[2] = v;
}
EXPORT_SYMBOL(pa_set_tag);

/* Only when @c: a record is made only if the load executes. */
noinline u64 pa_maybe(struct pa_state *s, int c)
{
	return c ? s->id : 0;
}
EXPORT_SYMBOL(pa_maybe);

/* Changes s->id behind pa_bump()'s back. */
noinline void pa_twice(struct pa_state *p)
{
	p->id *= 2;
}
EXPORT_SYMBOL(pa_twice);

/*
 * Load and store, an opaque call that changes the member, load and store
 * again: four records of one member, each with the value of that moment.
 */
noinline u64 pa_bump(struct pa_state *s)
{
	s->id++;
	pa_twice(s);
	return ++s->id;
}
EXPORT_SYMBOL(pa_bump);

/* The member under the lock: the record is the value read under it. */
noinline u32 pa_locked(struct pa_state *s)
{
	u32 v;

	spin_lock(&s->lock);
	v = s->in.x;
	spin_unlock(&s->lock);
	return v;
}
EXPORT_SYMBOL(pa_locked);

/* container_of: the key lies before the pointer, at a negative offset. */
noinline u64 pa_key(struct list_head *l)
{
	return container_of(l, struct pa_item, link)->key;
}
EXPORT_SYMBOL(pa_key);

/*
 * READ_ONCE()/WRITE_ONCE() are volatile accesses (recorded with
 * CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS_VOLATILE); atomic_inc() is inline
 * assembly, never recorded.
 */
noinline u64 pa_once(struct pa_state *s)
{
	u64 v = READ_ONCE(s->id);

	WRITE_ONCE(s->in.y, 0x77);
	atomic_inc(&s->refs);
	return v;
}
EXPORT_SYMBOL(pa_once);

/* Bit-fields: one byte load holds both members. */
noinline unsigned int pa_bits(struct pa_state *s)
{
	return s->flag + s->mode;
}
EXPORT_SYMBOL(pa_bits);

/* A 16-byte value, recorded as two 8-byte pieces. */
noinline u64 pa_wide(unsigned __int128 *p)
{
	unsigned __int128 v = *p;

	return (u64)v ^ (u64)(v >> 64);
}
EXPORT_SYMBOL(pa_wide);

/*
 * Recursion: every level's load belongs to that level's call. The load
 * follows the recursive call, behind a compiler barrier, so that the
 * recursion stays one (no tail-recursion elimination into a loop) and each
 * level loads s->in.x itself after its callee has returned.
 */
noinline u64 pa_depth(struct pa_state *s, int n)
{
	u64 r;

	if (n <= 0)
		return s->id;
	r = pa_depth(s, n - 1);
	barrier();
	return r + s->in.x;
}
EXPORT_SYMBOL(pa_depth);

/* Through a pointer loaded from the pointee: not followed. */
struct pa_holder {
	struct pa_state *state;
};

u64 pa_indirect(struct pa_holder *h);

noinline u64 pa_indirect(struct pa_holder *h)
{
	return h->state->id;
}
EXPORT_SYMBOL(pa_indirect);

/*
 * A memcpy() too large for the compiler to turn into loads and stores is no
 * access the record could take a value from.
 */
struct pa_blob {
	u8 b[256];
};

void pa_copy(struct pa_blob *dst, const struct pa_blob *src);

noinline void pa_copy(struct pa_blob *dst, const struct pa_blob *src)
{
	memcpy(dst, src, sizeof(*dst));
}
EXPORT_SYMBOL(pa_copy);

static struct dentry *test_dir;

static ssize_t trigger_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct pa_state *s = kzalloc(sizeof(*s), GFP_KERNEL);
	struct pa_item item = { .key = 0x4b4559 };
	struct pa_holder holder;
	struct pa_blob *blobs = kcalloc(2, sizeof(*blobs), GFP_KERNEL);
	unsigned __int128 wide;
	u64 sum = 0;

	if (!s || !blobs) {
		kfree(s);
		kfree(blobs);
		return -ENOMEM;
	}
	s->id = 100;
	s->in.x = 5;
	s->in.y = 6;
	s->flag = 5;
	s->mode = 17;
	spin_lock_init(&s->lock);
	atomic_set(&s->refs, 1);
	INIT_LIST_HEAD(&item.link);
	holder.state = s;
	wide = ((unsigned __int128)0x1122334455667788ULL << 64) |
	       0x99aabbccddeeff00ULL;

	sum += pa_get(s);			/* x=5, y=6 */
	pa_set_tag(s, 42);			/* tag[2]=42 */
	sum += pa_maybe(s, 0);			/* nothing */
	sum += pa_maybe(s, 1);			/* id=100 */
	sum += pa_bump(s);			/* 100 -> 101, 202 -> 203 */
	sum += pa_locked(s);			/* x=5 */
	sum += pa_key(&item.link);		/* key at -8 */
	sum += pa_once(s);			/* id=203, y=0x77 */
	sum += pa_bits(s);			/* flag=5, mode=17 */
	sum += pa_wide(&wide);
	sum += pa_depth(s, 2);			/* x, x, id */
	sum += pa_indirect(&holder);		/* only h->state */
	pa_copy(&blobs[0], &blobs[1]);		/* nothing */

	OPTIMIZER_HIDE_VAR(sum);
	kfree(blobs);
	kfree(s);
	return count;
}

static const struct file_operations trigger_fops = {
	.write = trigger_write,
};

static int __init pointee_access_init(void)
{
	test_dir = debugfs_create_dir("kcov_dataflow_test", NULL);
	debugfs_create_file("trigger_access", 0200, test_dir, NULL,
			    &trigger_fops);
	return 0;
}

static void __exit pointee_access_exit(void)
{
	debugfs_remove_recursive(test_dir);
}

module_init(pointee_access_init);
module_exit(pointee_access_exit);
