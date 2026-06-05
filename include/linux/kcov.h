/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KCOV_H
#define _LINUX_KCOV_H

#include <linux/sched.h>
#include <linux/jump_label.h>
#include <uapi/linux/kcov.h>

struct task_struct;

#ifdef CONFIG_KCOV

enum kcov_mode {
	/* Coverage collection is not enabled yet. */
	KCOV_MODE_DISABLED = 0,
	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
	KCOV_MODE_INIT = 1,
	/*
	 * Tracing coverage collection mode.
	 * Covered PCs are collected in a per-task buffer.
	 */
	KCOV_MODE_TRACE_PC = 2,
	/* Collecting comparison operands mode. */
	KCOV_MODE_TRACE_CMP = 3,
};

#define KCOV_IN_CTXSW	(1 << 30)

void kcov_task_init(struct task_struct *t);
void kcov_task_exit(struct task_struct *t);

#if defined(CONFIG_KCOV_DATAFLOW_ARGS) || defined(CONFIG_KCOV_DATAFLOW_RET)
void kcov_dataflow_task_init(struct task_struct *t);
void kcov_dataflow_task_exit(struct task_struct *t);
#else
static inline void kcov_dataflow_task_init(struct task_struct *t) {}
static inline void kcov_dataflow_task_exit(struct task_struct *t) {}
#endif

#define kcov_prepare_switch(t)			\
do {						\
	(t)->kcov_mode |= KCOV_IN_CTXSW;	\
} while (0)

#define kcov_finish_switch(t)			\
do {						\
	(t)->kcov_mode &= ~KCOV_IN_CTXSW;	\
} while (0)

/* See Documentation/dev-tools/kcov.rst for usage details. */
void kcov_remote_start(u64 handle);
void kcov_remote_stop(void);
struct kcov_common_handle_id kcov_common_handle(void);

static inline void kcov_remote_start_common(struct kcov_common_handle_id id)
{
	kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, id.val));
}

static inline void kcov_remote_start_usb(u64 id)
{
	kcov_remote_start(kcov_remote_handle(KCOV_SUBSYSTEM_USB, id));
}

/*
 * The softirq flavor of kcov_remote_*() functions is introduced as a temporary
 * work around for kcov's lack of nested remote coverage sections support in
 * task context. Adding support for nested sections is tracked in:
 * https://bugzilla.kernel.org/show_bug.cgi?id=210337
 */

static inline void kcov_remote_start_usb_softirq(u64 id)
{
	if (in_serving_softirq() && !in_hardirq())
		kcov_remote_start_usb(id);
}

static inline void kcov_remote_stop_softirq(void)
{
	if (in_serving_softirq() && !in_hardirq())
		kcov_remote_stop();
}

#ifdef CONFIG_64BIT
typedef unsigned long kcov_u64;
#else
typedef unsigned long long kcov_u64;
#endif

void __sanitizer_cov_trace_pc(void);
void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
void __sanitizer_cov_trace_cmp8(kcov_u64 arg1, kcov_u64 arg2);
void __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2);
void __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2);
void __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2);
void __sanitizer_cov_trace_const_cmp8(kcov_u64 arg1, kcov_u64 arg2);
void __sanitizer_cov_trace_switch(kcov_u64 val, void *cases);

#else

static inline void kcov_task_init(struct task_struct *t) {}
static inline void kcov_task_exit(struct task_struct *t) {}
static inline void kcov_prepare_switch(struct task_struct *t) {}
static inline void kcov_finish_switch(struct task_struct *t) {}
static inline void kcov_remote_start(u64 handle) {}
static inline void kcov_remote_stop(void) {}
static inline struct kcov_common_handle_id kcov_common_handle(void)
{
	return (struct kcov_common_handle_id){};
}
static inline void kcov_remote_start_common(struct kcov_common_handle_id id) {}
static inline void kcov_remote_start_usb(u64 id) {}
static inline void kcov_remote_start_usb_softirq(u64 id) {}
static inline void kcov_remote_stop_softirq(void) {}

#endif /* CONFIG_KCOV */

/* kcov_dataflow remote API (independent of CONFIG_KCOV) */
void kcov_df_remote_start(u64 handle);
void kcov_df_remote_stop(void);
#if defined(CONFIG_KCOV_ENABLE_COMPARISONS) && \
	(defined(CONFIG_KCOV_DATAFLOW_ARGS) || defined(CONFIG_KCOV_DATAFLOW_RET))
/*
 * CONFIG_KCOV_ENABLE_COMPARISONS provides ONE trace-cmp instrumentation shared by
 * mainline kcov and kcov-dataflow. kcov.c's __sanitizer_cov_trace_cmp*() callbacks
 * route each operand pair through kcov_trace_cmp() below. A task collects cmp for
 * at most ONE of the two collectors, so route to whichever is enabled at runtime:
 * a dataflow session takes the comparison into the dataflow buffer; otherwise it
 * goes to mainline kcov (write_comp_data records only in KCOV_MODE_TRACE_CMP). So
 * kcov.c never references the dataflow side, one cmp symbol feeds either collector,
 * and there is no separate df_cmp symbol or compiler change.
 *
 * The dataflow branch is gated by a static key so that, while no dataflow session
 * is live, this whole-kernel hot path is a patched-out NOP that falls straight to
 * mainline write_comp_data() -- zero added cost until a dataflow collector turns
 * on (kcov_df_cmp_key is inc'd on dataflow enable in kcov_dataflow.c).
 */
DECLARE_STATIC_KEY_FALSE(kcov_df_cmp_key);
void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip);
void kcov_df_trace_cmp(u64 type, u64 arg1, u64 arg2, u64 ip);
static inline notrace void
kcov_trace_cmp(u64 type, u64 arg1, u64 arg2, u64 ip)
{
	if (static_branch_unlikely(&kcov_df_cmp_key) && current->kcov_df_enabled)
		kcov_df_trace_cmp(type, arg1, arg2, ip);	/* kcov-dataflow */
	else
		write_comp_data(type, arg1, arg2, ip);		/* mainline kcov */
}
#elif defined(CONFIG_KCOV_ENABLE_COMPARISONS)
/* Comparisons without a dataflow build: route straight to mainline kcov. */
void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip);
static inline notrace void
kcov_trace_cmp(u64 type, u64 arg1, u64 arg2, u64 ip)
{
	write_comp_data(type, arg1, arg2, ip);
}
#endif
#endif /* _LINUX_KCOV_H */
