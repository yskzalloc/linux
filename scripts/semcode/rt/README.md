# PREEMPT_RT Atomic Sleep Detector

Static analysis tool that uses [semcode](https://github.com/masoncl/semcode) to
find potential sleeping-in-atomic-context bugs on `PREEMPT_RT` kernels.

## The Problem

On `PREEMPT_RT`, `spin_lock()` becomes a sleeping lock (`rt_mutex`). Code that
disables IRQs or preemption and then calls `spin_lock()` will crash:

```c
local_irq_save(flags);
spin_lock(&lock);       // BUG: sleeps on PREEMPT_RT!
```

This also applies **indirectly** through call chains:

```c
gfs2_quota_init() {
    spin_lock_bucket(hash);     // → bit_spin_lock → preempt_disable
    gfs2_glock_put(qd->qd_gl); // → ... → spin_lock (sleeps!)
}
```

## Quick Start

```bash
# 1. Index the kernel (one-time, ~2 minutes)
cd linux
semcode-index -s .

# 2. Run the detector
scripts/semcode/rt/detect_potential_atomic_sleep.py .

# Or run only direct/indirect mode:
scripts/semcode/rt/detect_potential_atomic_sleep.py . --mode direct
scripts/semcode/rt/detect_potential_atomic_sleep.py . --mode indirect

# Adjust call chain depth (default: 3):
scripts/semcode/rt/detect_potential_atomic_sleep.py . --depth 4
```

## How It Works

### Direct Detection (~30 seconds)

Finds functions that **directly** call both a disable function and a sleep function:

```
┌─────────────────────────────────────────────────────┐
│  1. Load call graph from semcode (JSON dump)        │
│  2. Find functions calling BOTH disable AND sleep   │
│  3. Fetch function body, check ordering:            │
│     disable → [no enable in between] → sleep = BUG │
└─────────────────────────────────────────────────────┘
```

### Indirect Detection (~2.5 minutes at depth=3)

Finds functions where the disable/sleep happens through **call chains**:

```
┌─────────────────────────────────────────────────────┐
│  1. Load call graph                                 │
│  2. Build "unbalanced disablers" — functions that   │
│     call disable but NOT the corresponding enable   │
│     (they leave the caller in atomic context)       │
│  3. Propagate transitively up to --depth levels     │
│  4. Find functions calling both a disabler chain    │
│     AND a sleeper chain                             │
│  5. Verify ordering in function body                │
└─────────────────────────────────────────────────────┘
```

## What Counts as "Disable" (Atomic Context)

| Function | Why |
|----------|-----|
| `local_irq_save()` | Disables IRQs — can't sleep |
| `local_irq_disable()` | Same |
| `preempt_disable()` | Disables preemption — can't sleep |
| `raw_spin_lock()` | Real spinlock on RT, disables preemption |
| `bit_spin_lock()` | Calls `preempt_disable()`, leaves it disabled |

## What Counts as "Sleep" on RT

| Function | Why |
|----------|-----|
| `spin_lock()` | Becomes `rt_mutex` (sleeping) on RT |
| `spin_lock_bh()` | Same |
| `kmalloc()` / `kzalloc()` | Internal SLUB locks sleep on RT |
| `folio_lock()` / `lock_page()` | Calls `might_sleep()` unconditionally |

## What is NOT a Problem

| Pattern | Why it's fine |
|---------|---------------|
| `local_bh_disable()` + `spin_lock()` | BH disable is sleepable on RT |
| `spin_lock_irqsave()` | Handles RT correctly internally |
| `raw_spin_lock()` + `raw_spin_lock()` | Both are non-sleeping on RT |
| Balanced functions (disable + enable) | Suit goes on AND off before return |

## False Positive Handling

The tool filters out known false positives:

- **Non-RT architectures** — alpha, parisc, powerpc, mips, etc.
- **Panic/oops paths** — machine is dying, RT correctness irrelevant
- **Balanced disablers** — functions that call both begin/end internally
- **64-bit no-ops** — `u64_stats_update_begin_irqsave` is empty on 64-bit
- **Test code** — `tools/testing/` paths
- **Misparsed macros** — `list_for_each_entry` etc. (tree-sitter artifacts)

## Example Output

```
## DIRECT violations (11)

drivers/md/raid5-ppl.c:ppl_io_unit_finished():
  local_irq_save(flags);
  -> spin_lock(&log->io_list_lock);  [sleeps on PREEMPT_RT]

## INDIRECT violations (41)

fs/gfs2/quota.c:gfs2_quota_init():
  spin_lock_bucket(hash);
    chain: spin_lock_bucket → hlist_bl_lock → bit_spin_lock
  -> gfs2_glock_put(qd->qd_gl);
    chain: gfs2_glock_put → __gfs2_glock_put → gfs2_glock_remove_from_lru → spin_lock
```

## Requirements

- Python 3.8+
- `semcode` and `semcode-index` binaries in PATH (or adjust the script)
- An indexed kernel: `semcode-index -s .`
