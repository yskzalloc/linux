// SPDX-License-Identifier: GPL-2.0
/*
 * KCOV Dataflow: per-task function argument/return value capture.
 *
 * Exposes /sys/kernel/debug/kcov_dataflow, completely independent from
 * /sys/kernel/debug/kcov. Own buffer, own ioctl, own mmap.
 *
 * TLV record layout (all u64):
 *   area[0]: total u64 words written (counter)
 *   [pos+0]: type_and_seq (0xE=entry, 0xF=return in upper 4 bits)
 *   [pos+1]: PC
 *   [pos+2]: meta (arg_idx | arg_size | ptr)
 *   [pos+3..N]: field values read via copy_from_kernel_nofault()
 */
#define pr_fmt(fmt) "kcov_dataflow: " fmt

#define DISABLE_BRANCH_PROFILING
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/shrinker.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/jump_label.h>
#include <linux/kcov.h>

/* Comparison capture is shared with mainline kcov; it only exists when both the
 * trace-cmp instrumentation and the dataflow task state are configured in. */
#if defined(CONFIG_KCOV_ENABLE_COMPARISONS) && \
	(defined(CONFIG_KCOV_DATAFLOW_ARGS) || defined(CONFIG_KCOV_DATAFLOW_RET))
#define KCOV_DF_HAVE_CMP 1
#endif

#define KCOV_DF_TYPE_ENTRY	0xE0000000ULL
#define KCOV_DF_TYPE_RET	0xF0000000ULL
#define KCOV_DF_TYPE_CMP	0xC0000000ULL
#define KCOV_DF_MAGIC_BAD	0xBADADD85ULL
#define KCOV_DF_IS_ERR(p)	((unsigned long)(p) >= (unsigned long)-4095UL)

/* Ioctl commands for /sys/kernel/debug/kcov_dataflow */
#define KCOV_DF_INIT_TRACK	_IOR('d', 1, unsigned long)
#define KCOV_DF_ENABLE		_IO('d', 100)
#define KCOV_DF_DISABLE		_IO('d', 101)
#define KCOV_DF_REMOTE_ENABLE	_IOW('d', 102, unsigned long)
#define KCOV_DF_REMOTE_DISABLE	_IO('d', 103)

/*
 * Per-worker private scratch size (u64 words), KCOV's remote-area model: a
 * remote kworker collects into its OWN scratch and merges it into the shared
 * ->area at kcov_df_remote_stop(). Fixed and small (8 MiB) -- one work item's
 * coverage, not a whole buffer -- so the pool of recycled scratch areas stays
 * bounded regardless of how many kworkers churn. Overflowing a scratch just
 * drops that worker's excess records (same as a full buffer), never corrupts.
 */
#define KCOV_DF_REMOTE_WORDS	(1UL << 20)

struct kcov_dataflow {
	struct mutex	lock;
	unsigned int	size;	/* in u64 words */
	void		*area;
	struct task_struct *t;
	/*
	 * Lifetime refcount (KCOV's struct kcov pattern). The open fd holds one
	 * ref; each kcov_df_remote_start() takes one and the matching
	 * kcov_df_remote_stop() drops it. Whoever drops the LAST ref frees
	 * ->area and the object (kcov_df_put). This replaces the old
	 * "while (remote_refs > 0) cond_resched()" drain in close(), which could
	 * wedge forever when a remote_stop's decrement was lost to an already
	 * unpublished hash entry.
	 */
	refcount_t	refcount;
	u64		remote_handle; /* handle for remote lookup, 0 if not published */
#ifdef KCOV_DF_HAVE_CMP
	/*
	 * Whether this fd holds a ref on kcov_df_cmp_key, tracked SEPARATELY for
	 * the local (KCOV_DF_ENABLE) and remote (KCOV_DF_REMOTE_ENABLE) sources.
	 * A single shared flag let a KCOV_DF_DISABLE drop the key while a remote
	 * handle was still published -- silently routing the live remote workers'
	 * trace-cmp to mainline kcov and losing every comparison record. Two flags mean
	 * releasing one source never pulls the key out from under the other.
	 */
	bool		cmp_key_local;
	bool		cmp_key_remote;
#endif
};

/* Which activation source holds the cmp static key (see kcov_df_cmp_key_hold). */
enum { KCOV_DF_CMP_LOCAL, KCOV_DF_CMP_REMOTE };

#ifdef KCOV_DF_HAVE_CMP
/*
 * Static key gating the per-comparison dataflow check in kcov_trace_cmp()
 * (linux/kcov.h). It is a patched-out NOP until at least one dataflow session is
 * live, so trace-cmp across the WHOLE kernel costs nothing extra while no
 * dataflow fuzzing runs; only an active session flips it on. Refcounted: inc on
 * each source's first enable, dec on its disable/close (idempotent, tracked per
 * source via cmp_key_local / cmp_key_remote so releasing one never drops the key
 * from under the other).
 * The static_branch_{inc,dec}() text-patch is amortised -- it fires only on the
 * 0->1 and 1->0 transitions, not per fd while sessions overlap.
 */
DEFINE_STATIC_KEY_FALSE(kcov_df_cmp_key);
EXPORT_SYMBOL(kcov_df_cmp_key);

static void kcov_df_cmp_key_hold(struct kcov_dataflow *df, int which)
{
	bool *held = which == KCOV_DF_CMP_LOCAL ? &df->cmp_key_local
						: &df->cmp_key_remote;

	if (!*held) {
		*held = true;
		static_branch_inc(&kcov_df_cmp_key);
	}
}

static void kcov_df_cmp_key_release(struct kcov_dataflow *df, int which)
{
	bool *held = which == KCOV_DF_CMP_LOCAL ? &df->cmp_key_local
						: &df->cmp_key_remote;

	if (*held) {
		*held = false;
		static_branch_dec(&kcov_df_cmp_key);
	}
}
#else
static void kcov_df_cmp_key_hold(struct kcov_dataflow *df, int which) {}
static void kcov_df_cmp_key_release(struct kcov_dataflow *df, int which) {}
#endif

/* Remote dataflow: handle-based lookup (follows KCOV's kcov_remote_map pattern) */
static DEFINE_MUTEX(kcov_df_remote_lock);
static DEFINE_HASHTABLE(kcov_df_remote_map, 4);

struct kcov_df_remote {
	u64			handle;
	struct kcov_dataflow	*df;
	struct hlist_node	hnode;
};

static struct kcov_df_remote *kcov_df_remote_find(u64 handle)
{
	struct kcov_df_remote *remote;

	hash_for_each_possible(kcov_df_remote_map, remote, hnode, handle) {
		if (remote->handle == handle)
			return remote;
	}
	return NULL;
}

static void kcov_df_get(struct kcov_dataflow *df)
{
	refcount_inc(&df->refcount);
}

/*
 * Drop a reference; the last one frees the buffer and the object. Safe to call
 * from process/worker context (in_task()) where kcov_df_remote_stop() runs, so
 * vfree() here is fine. No caller may touch @df after its own kcov_df_put().
 */
static void kcov_df_put(struct kcov_dataflow *df)
{
	if (refcount_dec_and_test(&df->refcount)) {
		/* Balance any still-held cmp key refs (both idempotent). */
		kcov_df_cmp_key_release(df, KCOV_DF_CMP_LOCAL);
		kcov_df_cmp_key_release(df, KCOV_DF_CMP_REMOTE);
		vfree(df->area);
		kfree(df);
	}
}

/*
 * Pool of recycled per-worker scratch areas (KCOV's kcov_remote_areas). All are
 * KCOV_DF_REMOTE_WORDS u64s. While parked on the freelist the area's first bytes
 * hold this list_head; while in use word[0] is the scratch write cursor. Guarded
 * by kcov_df_remote_lock.
 */
struct kcov_df_scratch {
	struct list_head list;
};
static LIST_HEAD(kcov_df_scratch_pool);
static unsigned long kcov_df_scratch_pool_nr;	/* idle areas parked in the pool */

/* Take a scratch area from the pool, or NULL if empty (caller vmalloc()s one). */
static void *kcov_df_scratch_get(void)
{
	struct kcov_df_scratch *s;

	if (list_empty(&kcov_df_scratch_pool))
		return NULL;
	s = list_first_entry(&kcov_df_scratch_pool, struct kcov_df_scratch, list);
	list_del(&s->list);
	kcov_df_scratch_pool_nr--;
	return s;
}

/* Return a scratch area to the pool for reuse. */
static void kcov_df_scratch_put(void *area)
{
	struct kcov_df_scratch *s = area;

	INIT_LIST_HEAD(&s->list);
	list_add(&s->list, &kcov_df_scratch_pool);
	kcov_df_scratch_pool_nr++;
}

/*
 * Merge a remote worker's private scratch into the shared ->area, appending its
 * records at the shared write cursor. This is the ONE many-writers path (several
 * kworkers merge concurrently), so it reserves its region with an atomic add and
 * NEVER undoes on reject -- an atomic64_sub "undo" could race userspace resetting
 * the counter (writing ->area[0]=0 to restart collection), drive the shared counter
 * negative, wrap the base huge and bypass the bounds check into a wild OOB store.
 * Without the sub the counter only grows until the next reset, so it can never go
 * negative; each merge claims
 * a disjoint [start, start+n), so concurrent merges don't overlap and need no
 * lock. @df is kept alive by the caller's reference, so ->area is stable here.
 */
static void kcov_df_merge(struct kcov_dataflow *df, const u64 *scratch)
{
	u64 *area = df->area;
	u64 n, base, start;

	if (!area)
		return;
	/*
	 * scratch[0] is an EXACT high-water of written words: kcov_df_reserve()
	 * commits the count only after a record fits, so every counted word was
	 * really written -- the merge never publishes the unwritten
	 * (recycled/uninitialized) tail of a pooled scratch. The clamp below is thus
	 * belt-and-suspenders against a stray count.
	 */
	n = scratch[0];
	if (n > KCOV_DF_REMOTE_WORDS - 1)
		n = KCOV_DF_REMOTE_WORDS - 1;
	if (!n)
		return;

	base = atomic64_add_return(n, (atomic64_t *)&area[0]) - n;
	start = 1 + base;
	/* Overflow-safe, no undo (see the function comment): drop on full. */
	if (base >= df->size || n > df->size - start)
		return;
	memcpy(&area[start], &scratch[1], n * sizeof(u64));
}

/*
 * Reserve @record_len u64 words in the current task's buffer. On success return
 * true and store the 1-based start index of the record's data region.
 *
 * Single-writer discipline, identical to mainline kcov.c: the current task is the
 * ONLY instrumented writer of @area. In remote mode @area is this kworker's OWN
 * private scratch; in local (KCOV_DF_ENABLE) mode it is the enabling task's own
 * mmapped buffer -- and only one task can hold that (the KCOV_DF_ENABLE EBUSY
 * guard). Two tasks never write the same @area here, so no atomic is needed:
 * validate FIRST and commit the count (area[0]) only on success, so area[0] is
 * always an EXACT high-water of written words and no consumer (userspace or
 * kcov_df_merge()) ever sees an unwritten/recycled slot.
 *
 * (Publishing a worker's scratch into the shared ->area is the SEPARATE
 * kcov_df_merge() path, which DOES reserve atomically because many kworkers merge
 * concurrently.)
 *
 * READ_ONCE/WRITE_ONCE because in local mode userspace may reset area[0] to 0
 * between operations. That reset can only drive the count to 0, never negative
 * (there is no subtract), so a racing reset may drop records but can never produce
 * an out-of-bounds store. This is exactly mainline kcov's contract.
 */
static notrace __no_sanitize_coverage bool
kcov_df_reserve(struct task_struct *t, u64 *area, u32 record_len,
		unsigned long *start_index)
{
	unsigned long count = READ_ONCE(area[0]);

	*start_index = 1 + count;
	if (count >= t->kcov_df_size ||
	    record_len > t->kcov_df_size - *start_index)
		return false;
	WRITE_ONCE(area[0], count + record_len);
	return true;
}

/*
 * Contexts where dataflow collection must stay completely inert.
 *
 * Beyond the obvious !in_task() case, this bails whenever page faults are
 * disabled. copy_from_kernel_nofault() -- used by kcov_df_write() below to read
 * traced pointers, and, crucially, by the ORC stack unwinder that KASAN runs on
 * every slab free (set_track_prepare() -> stack_trace_save()) -- brackets its
 * raw loads with pagefault_disable(), and those loads carry trace-cmp/trace-args
 * instrumentation. Without this bail a single stack walk under a fuzzing + KASAN
 * workload floods the collector with a callback per load and soft-locks the CPU.
 *
 * pagefault_disabled() is true throughout any such nofault region no matter
 * which instrumented leaf issued the callback, so testing it here contains the
 * whole class of self-instrumentation storms -- the bit-31 recursion guard below
 * only covers re-entry nested inside our own callback, not a fresh entry from
 * the unwinder/KASAN path. Contained entirely to this file: no coverage
 * exclusion in mm/ or arch/ is needed.
 */
static __always_inline notrace __no_sanitize_coverage bool
kcov_df_inert_context(void)
{
	return !in_task() || pagefault_disabled();
}

/*
 * Core write function for dataflow records.
 * Uses the same READ_ONCE/WRITE_ONCE pattern as write_comp_data() in kcov.c.
 */
static noinline notrace __no_sanitize_coverage void
kcov_df_write(u64 type_marker, u64 pc, u64 meta, void *ptr,
	      u64 *offsets, u32 num_fields)
{
	struct task_struct *t = current;
	u64 *area;
	unsigned long start_index;
	u32 record_len, seq, i;

	if (kcov_df_inert_context())
		return;

	if (!t->kcov_df_enabled)
		return;

	/*
	 * Prevent recursion: functions called by this callback
	 * (copy_from_kernel_nofault) may be instrumented. Use the
	 * sequence counter's high bit as a per-task guard.
	 */
	if (t->kcov_df_seq & (1U << 31))
		return;
	t->kcov_df_seq |= (1U << 31);

	area = (u64 *)t->kcov_df_area;
	if (!area)
		goto out;

	/* Record: header(1) + pc(1) + meta(1) + fields or scalar(max 1) */
	record_len = 3 + (num_fields > 0 ? num_fields : 1);

	if (!kcov_df_reserve(t, area, record_len, &start_index))
		goto out;

	seq = ++t->kcov_df_seq;
	area[start_index] = type_marker |
			    ((u64)(record_len - 3) << 24) |
			    (seq & 0x00FFFFFFULL);
	area[start_index + 1] = pc;
	area[start_index + 2] = meta;

	if (num_fields == 0) {
		u64 val = 0;
		u32 sz = (meta >> 48) & 0xFF;

		/*
		 * Read the scalar with a compile-time-constant width for the
		 * common sizes so the compiler folds away copy_from_kernel_
		 * nofault()'s runtime size loop and alignment branching; fall
		 * back to the variable-size byte copy for anything else. A
		 * faulting read leaves val == 0, matching the prior best-effort
		 * behaviour.
		 */
		if (ptr && !KCOV_DF_IS_ERR(ptr)) {
			switch (sz) {
			case 8: {
				u64 v = 0;

				if (!get_kernel_nofault(v, (u64 *)ptr))
					val = v;
				break;
			}
			case 4: {
				u32 v = 0;

				if (!get_kernel_nofault(v, (u32 *)ptr))
					val = v;
				break;
			}
			case 2: {
				u16 v = 0;

				if (!get_kernel_nofault(v, (u16 *)ptr))
					val = v;
				break;
			}
			case 1: {
				u8 v = 0;

				if (!get_kernel_nofault(v, (u8 *)ptr))
					val = v;
				break;
			}
			default:
				if (sz > sizeof(val))
					sz = sizeof(val);
				copy_from_kernel_nofault(&val, ptr, sz);
			}
		}
		area[start_index + 3] = val;
	} else {
		if (!ptr || KCOV_DF_IS_ERR(ptr)) {
			for (i = 0; i < num_fields; i++)
				area[start_index + 3 + i] = KCOV_DF_MAGIC_BAD;
			goto out;
		}
		for (i = 0; i < num_fields; i++) {
			u64 off, sz, val = KCOV_DF_MAGIC_BAD;
			void *fa;

			if (copy_from_kernel_nofault(&off, &offsets[i * 2], sizeof(off)) ||
			    copy_from_kernel_nofault(&sz, &offsets[i * 2 + 1], sizeof(sz))) {
				area[start_index + 3 + i] = KCOV_DF_MAGIC_BAD;
				continue;
			}
			fa = (void *)((unsigned long)ptr + off);
			val = 0;

			if (sz <= sizeof(val)) {
				if (copy_from_kernel_nofault(&val, fa, sz))
					val = KCOV_DF_MAGIC_BAD;
			} else {
				if (copy_from_kernel_nofault(&val, fa, sizeof(val)))
					val = KCOV_DF_MAGIC_BAD;
			}
			area[start_index + 3 + i] = val;
		}
	}
out:
	barrier();
	/*
	 * Paired with the barrier() after setting bit-31 at the top.
	 * Ensures all record writes are complete before we clear the
	 * recursion guard.
	 */
	t->kcov_df_seq &= ~(1U << 31);
}

#ifdef CONFIG_KCOV_DATAFLOW_ARGS
noinline void notrace __no_sanitize_coverage
__sanitizer_cov_trace_args(u64 pc, u32 arg_idx, u32 arg_size, void *arg_ptr,
			   u64 *offsets, u32 num_fields);

noinline void notrace __no_sanitize_coverage
__sanitizer_cov_trace_args(u64 pc, u32 arg_idx, u32 arg_size, void *arg_ptr,
			   u64 *offsets, u32 num_fields)
{
	u64 meta = ((u64)arg_idx << 56) | ((u64)arg_size << 48) |
		   ((u64)(unsigned long)arg_ptr & 0xFFFFFFFFFFFFULL);
	kcov_df_write(KCOV_DF_TYPE_ENTRY, pc, meta, arg_ptr,
		      offsets, num_fields);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_args);
#endif

#ifdef CONFIG_KCOV_DATAFLOW_RET
noinline void notrace __no_sanitize_coverage
__sanitizer_cov_trace_ret(u64 pc, u32 ret_size, void *ret_val,
			  u64 *offsets, u32 num_fields);

noinline void notrace __no_sanitize_coverage
__sanitizer_cov_trace_ret(u64 pc, u32 ret_size, void *ret_val,
			  u64 *offsets, u32 num_fields)
{
	u64 meta = ((u64)ret_size << 48) |
		   ((u64)(unsigned long)ret_val & 0xFFFFFFFFFFFFULL);
	kcov_df_write(KCOV_DF_TYPE_RET, pc, meta, ret_val,
		      offsets, num_fields);
}
EXPORT_SYMBOL(__sanitizer_cov_trace_ret);
#endif

#if defined(CONFIG_KCOV_ENABLE_COMPARISONS) && \
	(defined(CONFIG_KCOV_DATAFLOW_ARGS) || defined(CONFIG_KCOV_DATAFLOW_RET))
/*
 * Comparison capture (input-to-state). Reached from the shared
 * __sanitizer_cov_trace_cmp*() callbacks (kcov.c) via kcov_trace_cmp()
 * (linux/kcov.h), which routes here only when this task has a dataflow session,
 * so trace-cmp operand pairs land in the SAME unified TLV buffer as the arg/ret
 * records. Both operands are recorded, so a userspace consumer can use them for
 * input-to-state matching, complementing the arg/ret records.
 *
 * Record: [header(CMP|nfields=2|seq)][pc][cmp_type meta][arg1][arg2].
 * cmp_type carries KCOV_CMP_SIZE()/KCOV_CMP_CONST bits (see linux/kcov.h) so the
 * consumer knows operand width and whether one side was a compile-time constant.
 */
noinline notrace __no_sanitize_coverage void
kcov_df_trace_cmp(u64 cmp_type, u64 arg1, u64 arg2, u64 ip)
{
	struct task_struct *t = current;
	u64 *area;
	unsigned long start_index;
	const u32 record_len = 3 + 2;	/* header + pc + meta + arg1 + arg2 */
	u32 seq;

	if (kcov_df_inert_context())
		return;
	if (!t->kcov_df_enabled)
		return;
	/* Same recursion guard as kcov_df_write(): bit 31 of the seq counter. */
	if (t->kcov_df_seq & (1U << 31))
		return;
	t->kcov_df_seq |= (1U << 31);

	area = (u64 *)t->kcov_df_area;
	if (!area)
		goto out;

	/* Single-writer exact-count reservation: see kcov_df_reserve(). */
	if (!kcov_df_reserve(t, area, record_len, &start_index))
		goto out;

	seq = ++t->kcov_df_seq;
	area[start_index]     = KCOV_DF_TYPE_CMP |
				((u64)2 << 24) |		/* nfields */
				(seq & 0x00FFFFFFULL);
	area[start_index + 1] = ip;
	area[start_index + 2] = cmp_type;
	area[start_index + 3] = arg1;
	area[start_index + 4] = arg2;
out:
	barrier();
	t->kcov_df_seq &= ~(1U << 31);
}
EXPORT_SYMBOL(kcov_df_trace_cmp);
#endif /* CONFIG_KCOV_ENABLE_COMPARISONS */

/* Called from kernel/fork.c to clear inherited state. */
void kcov_dataflow_task_init(struct task_struct *t)
{
	t->kcov_df_area = NULL;
	t->kcov_df_size = 0;
	t->kcov_df_seq = 0;
	t->kcov_df_enabled = false;
	t->kcov_df_remote = NULL;
	t->kcov_df_remote_depth = 0;
}

/* Called from kernel/exit.c to clear state on task exit. */
void kcov_dataflow_task_exit(struct task_struct *t)
{
	struct kcov_dataflow *df = t->kcov_df_remote;

	if (df) {
		/*
		 * A remote kworker exited between kcov_df_remote_start() and
		 * _stop() (should not happen -- they bracket a single work item).
		 * Defensive: drop its partial scratch and release the ref so
		 * neither the buffer nor the object leaks.
		 */
		void *scratch = t->kcov_df_area;

		t->kcov_df_enabled = false;
		t->kcov_df_area = NULL;
		t->kcov_df_size = 0;
		t->kcov_df_remote = NULL;
		t->kcov_df_remote_depth = 0;
		vfree(scratch);
		kcov_df_put(df);
		return;
	}
	if (t->kcov_df_enabled) {
		/* Local (KCOV_DF_ENABLE) session on the exiting task. */
		t->kcov_df_enabled = false;
		t->kcov_df_area = NULL;
		t->kcov_df_size = 0;
	}
}

/* File operations for /sys/kernel/debug/kcov_dataflow */

static int kcov_df_open(struct inode *inode, struct file *filep)
{
	struct kcov_dataflow *df;

	df = kzalloc(sizeof(*df), GFP_KERNEL);
	if (!df)
		return -ENOMEM;
	mutex_init(&df->lock);
	refcount_set(&df->refcount, 1);	/* the open fd's reference */
	filep->private_data = df;
	return nonseekable_open(inode, filep);
}

static int kcov_df_close(struct inode *inode, struct file *filep)
{
	struct kcov_dataflow *df = filep->private_data;
	struct kcov_df_remote *remote;

	/* Unpublish from remote hash: no new users can start */
	mutex_lock(&kcov_df_remote_lock);
	if (df->remote_handle) {
		remote = kcov_df_remote_find(df->remote_handle);
		if (remote) {
			hash_del(&remote->hnode);
			kfree(remote);
		}
		df->remote_handle = 0;
	}
	mutex_unlock(&kcov_df_remote_lock);

	mutex_lock(&df->lock);
	if (df->t == current) {
		current->kcov_df_enabled = false;
		current->kcov_df_area = NULL;
		current->kcov_df_size = 0;
		df->t = NULL;
	}
	mutex_unlock(&df->lock);

	/*
	 * Drop the fd's reference. If remote workers still hold refs (they are
	 * between kcov_df_remote_start() and _stop()), the LAST of them frees
	 * ->area via kcov_df_put() -- no drain loop, no lost-decrement wedge.
	 * The hash entry was already unpublished above, so no new remote user
	 * can start on this object.
	 */
	kcov_df_put(df);
	return 0;
}

static int kcov_df_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct kcov_dataflow *df = filep->private_data;
	unsigned long size, off;
	struct page *page;
	void *area;
	int res = 0;

	mutex_lock(&df->lock);
	size = df->size * sizeof(u64);
	if (!df->area || vma->vm_pgoff != 0 ||
	    vma->vm_end - vma->vm_start != size) {
		res = -EINVAL;
		goto out;
	}
	area = df->area;
	mutex_unlock(&df->lock);

	vm_flags_set(vma, VM_DONTEXPAND);
	for (off = 0; off < size; off += PAGE_SIZE) {
		page = vmalloc_to_page(area + off);
		res = vm_insert_page(vma, vma->vm_start + off, page);
		if (res)
			return res;
	}
	return 0;
out:
	mutex_unlock(&df->lock);
	return res;
}

static long kcov_df_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	struct kcov_dataflow *df = filep->private_data;
	unsigned long size;
	int res = 0;

	mutex_lock(&df->lock);
	switch (cmd) {
	case KCOV_DF_INIT_TRACK:
		if (df->area) {
			res = -EBUSY;
			break;
		}
		size = arg;
		if (size < 2 || size > (128 << 20) / sizeof(u64)) {
			res = -EINVAL;
			break;
		}
		mutex_unlock(&df->lock);
		{
			void *area = vmalloc_user(size * sizeof(u64));

			if (!area)
				return -ENOMEM;
			mutex_lock(&df->lock);
			if (df->area) {
				mutex_unlock(&df->lock);
				vfree(area);
				return -EBUSY;
			}
			df->area = area;
			df->size = size;
		}
		break;

	case KCOV_DF_ENABLE:
		if (!df->area || df->t || current->kcov_df_enabled) {
			res = -EBUSY;
			break;
		}
		df->t = current;
		current->kcov_df_area = df->area;
		current->kcov_df_size = df->size;
		current->kcov_df_seq = 0;
		current->kcov_df_enabled = true;
		kcov_df_cmp_key_hold(df, KCOV_DF_CMP_LOCAL);
		break;

	case KCOV_DF_DISABLE:
		if (df->t != current) {
			res = -EINVAL;
			break;
		}
		current->kcov_df_enabled = false;
		current->kcov_df_area = NULL;
		current->kcov_df_size = 0;
		df->t = NULL;
		kcov_df_cmp_key_release(df, KCOV_DF_CMP_LOCAL);
		break;

	case KCOV_DF_REMOTE_ENABLE: {
		struct kcov_df_remote *remote;
		u64 handle = (u64)arg;

		if (!df->area || !handle) {
			res = -EINVAL;
			break;
		}
		remote = kzalloc(sizeof(*remote), GFP_KERNEL);
		if (!remote) {
			res = -ENOMEM;
			break;
		}
		remote->handle = handle;
		remote->df = df;
		mutex_lock(&kcov_df_remote_lock);
		if (kcov_df_remote_find(handle)) {
			mutex_unlock(&kcov_df_remote_lock);
			kfree(remote);
			res = -EEXIST;
			break;
		}
		hash_add(kcov_df_remote_map, &remote->hnode, handle);
		df->remote_handle = handle;
		mutex_unlock(&kcov_df_remote_lock);
		kcov_df_cmp_key_hold(df, KCOV_DF_CMP_REMOTE);
		break;
	}

	case KCOV_DF_REMOTE_DISABLE: {
		struct kcov_df_remote *remote;

		mutex_lock(&kcov_df_remote_lock);
		if (df->remote_handle) {
			remote = kcov_df_remote_find(df->remote_handle);
			if (remote) {
				hash_del(&remote->hnode);
				kfree(remote);
			}
			df->remote_handle = 0;
		}
		mutex_unlock(&kcov_df_remote_lock);
		kcov_df_cmp_key_release(df, KCOV_DF_CMP_REMOTE);
		break;
	}

	default:
		res = -ENOTTY;
	}
	mutex_unlock(&df->lock);
	return res;
}

/* Remote dataflow implementation */

void kcov_df_remote_start(u64 handle)
{
	struct kcov_df_remote *remote;
	struct kcov_dataflow *df;
	void *scratch;

	if (!handle)
		return;
	/* Dataflow remote coverage is collected in task (kworker) context only. */
	if (!in_task())
		return;
	/*
	 * A task should only run one remote session at a time (KCOV's rule). If a
	 * buggy caller nests, don't re-init and don't take a second ref -- just
	 * count the depth so the matching inner stop() leaves the outer session
	 * intact (see kcov_df_remote_stop()). Coverage from the nested region is
	 * attributed to the outer handle, which is safe (no corruption, no early
	 * free) even though it is imprecise.
	 */
	if (current->kcov_df_remote) {
		WARN_ON_ONCE(1);
		if (current->kcov_df_remote_depth < INT_MAX)
			current->kcov_df_remote_depth++;
		return;
	}

	mutex_lock(&kcov_df_remote_lock);
	remote = kcov_df_remote_find(handle);
	if (!remote || !remote->df || !remote->df->area) {
		mutex_unlock(&kcov_df_remote_lock);
		return;
	}
	df = remote->df;
	kcov_df_get(df);		/* keep @df (and ->area) alive until _stop() */
	scratch = kcov_df_scratch_get();	/* reuse a pooled scratch if any */
	mutex_unlock(&kcov_df_remote_lock);

	if (!scratch) {
		scratch = vmalloc(KCOV_DF_REMOTE_WORDS * sizeof(u64));
		if (!scratch) {
			kcov_df_put(df);
			return;
		}
	}
	((u64 *)scratch)[0] = 0;	/* reset the scratch write cursor */

	/*
	 * Point this task at its OWN private scratch, NOT df->area. It collects
	 * here while it runs; kcov_df_remote_stop() merges it into the shared
	 * buffer. So multiple kworkers on one handle never write the same buffer.
	 */
	current->kcov_df_area = scratch;
	current->kcov_df_size = KCOV_DF_REMOTE_WORDS;
	current->kcov_df_seq = 0;
	current->kcov_df_remote = df;	/* pocket it for _stop(); no hash relookup */
	current->kcov_df_remote_depth = 1;
	/*
	 * Publish all session state BEFORE the enable flag (mirrors kcov_start()).
	 * kcov_df_write() gates on kcov_df_enabled and then reads kcov_df_area, so
	 * the buffer/handle must be visible first; the barrier keeps the compiler
	 * from hoisting the enable above them.
	 */
	barrier();
	current->kcov_df_enabled = true;
}
EXPORT_SYMBOL_GPL(kcov_df_remote_start);

void kcov_df_remote_stop(void)
{
	struct kcov_dataflow *df = current->kcov_df_remote;
	void *scratch;

	if (!df)
		return;

	/*
	 * Unwind a nested start() (buggy caller): only the OUTERMOST stop tears
	 * the session down. Inner stops just decrement the depth and return, so
	 * the buffer/ref survive until the worker is really done with them.
	 */
	if (current->kcov_df_remote_depth > 1) {
		current->kcov_df_remote_depth--;
		return;
	}
	current->kcov_df_remote_depth = 0;

	scratch = current->kcov_df_area;

	/*
	 * Stop writing FIRST: clear the per-task pointers so this task can no
	 * longer enter kcov_df_write() / touch the scratch. Then it is safe to
	 * merge and recycle the scratch and drop the ref.
	 */
	current->kcov_df_enabled = false;
	current->kcov_df_area = NULL;
	current->kcov_df_size = 0;
	current->kcov_df_remote = NULL;

	if (scratch) {
		/* Publish this worker's records into the shared buffer, then
		 * return the scratch to the pool for the next worker. */
		kcov_df_merge(df, scratch);
		mutex_lock(&kcov_df_remote_lock);
		kcov_df_scratch_put(scratch);
		mutex_unlock(&kcov_df_remote_lock);
	}

	/*
	 * Drop the ref taken in kcov_df_remote_start(). If this is the last one,
	 * kcov_df_put() frees ->area right here -- safe, because no task writes
	 * ->area directly anymore (workers write scratch; the merge above is
	 * done). Dropping via the pocketed @df (not a hash lookup) means an
	 * already-unpublished entry can never strand the count.
	 */
	kcov_df_put(df);
}
EXPORT_SYMBOL_GPL(kcov_df_remote_stop);

static const struct file_operations kcov_df_fops = {
	.open		= kcov_df_open,
	.unlocked_ioctl	= kcov_df_ioctl,
	.compat_ioctl	= kcov_df_ioctl,
	.mmap		= kcov_df_mmap,
	.release	= kcov_df_close,
};

/*
 * Reclaim idle per-worker scratch under memory pressure. The pool otherwise only
 * ever grows to the peak number of concurrent remote kworkers (each area is 8 MiB)
 * and is never returned to the allocator; a shrinker lets the VM take the idle
 * (parked) areas back when it needs the memory. Only pooled areas are freeable;
 * in-use scratch is not on the list. mutex_trylock keeps the shrinker best-effort
 * and free of any lock-ordering risk.
 */
static unsigned long
kcov_df_scratch_shrink_count(struct shrinker *sh, struct shrink_control *sc)
{
	unsigned long nr;

	if (!mutex_trylock(&kcov_df_remote_lock))
		return 0;
	nr = kcov_df_scratch_pool_nr;
	mutex_unlock(&kcov_df_remote_lock);
	return nr ? nr : SHRINK_EMPTY;
}

static unsigned long
kcov_df_scratch_shrink_scan(struct shrinker *sh, struct shrink_control *sc)
{
	struct kcov_df_scratch *s, *tmp;
	LIST_HEAD(victims);
	unsigned long freed = 0;

	if (!mutex_trylock(&kcov_df_remote_lock))
		return SHRINK_STOP;
	/* Detach victims under the lock; free them (each 8 MiB) after unlocking so
	 * the vfree() latency stays off concurrent remote_start()/stop(). */
	while (freed < sc->nr_to_scan && !list_empty(&kcov_df_scratch_pool)) {
		s = list_first_entry(&kcov_df_scratch_pool,
				     struct kcov_df_scratch, list);
		list_move(&s->list, &victims);
		kcov_df_scratch_pool_nr--;
		freed++;
	}
	mutex_unlock(&kcov_df_remote_lock);

	list_for_each_entry_safe(s, tmp, &victims, list)
		vfree(s);
	return freed;
}

static int __init kcov_dataflow_init(void)
{
	struct shrinker *shrinker;

	debugfs_create_file_unsafe("kcov_dataflow", 0600, NULL, NULL,
				   &kcov_df_fops);

	shrinker = shrinker_alloc(0, "kcov-df-scratch");
	if (shrinker) {
		shrinker->count_objects = kcov_df_scratch_shrink_count;
		shrinker->scan_objects = kcov_df_scratch_shrink_scan;
		shrinker->seeks = DEFAULT_SEEKS;
		shrinker_register(shrinker);
	}
	return 0;
}
device_initcall(kcov_dataflow_init);
