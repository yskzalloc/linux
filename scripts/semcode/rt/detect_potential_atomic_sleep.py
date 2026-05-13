#!/usr/bin/env python3
"""
detect_potential_atomic_sleep.py - Detect PREEMPT_RT atomic sleep bugs using semcode

== The Problem (a metaphor) ==

Think of the CPU like a worker in a factory:

  - "local_irq_disable()" is like putting on a hazmat suit — you CANNOT stop
    to take a nap (sleep) until you take it off. You're in a critical zone.

  - "spin_lock()" on a normal kernel is like grabbing a tool — you just spin
    and wait if someone else has it. No sleeping involved.

  - But on PREEMPT_RT, "spin_lock()" becomes a SLEEPING lock (rt_mutex).
    It's like saying "I'll go take a nap until the tool is free."

  - So: hazmat suit ON + trying to nap = BUG! You can't sleep in a hazmat suit.

== Two detection modes ==

  DIRECT:   The function itself calls both disable and sleep.
            local_irq_save(flags);
            spin_lock(&lock);       // BUG on RT!

  INDIRECT: The function calls b() which disables, then c() which sleeps.
            a() {
                b();    // b() → preempt_disable() — suit ON
                c();    // c() → spin_lock() — tries to nap — BUG!
            }

== Why local_bh_disable() + spin_lock() is fine ==

  local_bh_disable() on RT is like putting on a light jacket — you CAN still
  nap in it. It becomes a sleepable per-CPU lock on RT, not a hard atomic
  context. So spin_lock() after it is perfectly safe.

Usage:
  ./detect_potential_atomic_sleep.py [kernel_dir] [--database path] [--depth N] [--mode direct|indirect|all]
"""

import json
import re
import subprocess
import sys
import os


# ═══════════════════════════════════════════════════════════════════════════════
# Constants — the "vocabulary" of atomic context and sleeping on RT
# ═══════════════════════════════════════════════════════════════════════════════

# ─── "Hazmat suit" functions ─────────────────────────────────────────────────
# These create a non-sleepable (atomic) context.
# Metaphor: once you call these, you're wearing the hazmat suit —
#           you CANNOT sleep until you take it off.
DISABLE_FNS = {
    'local_irq_save',           # Save IRQ state + disable IRQs
    'local_irq_disable',        # Disable IRQs directly
    'raw_local_irq_disable',    # Arch-level IRQ disable
    'arch_local_irq_disable',   # Lowest-level arch IRQ disable
    'preempt_disable',          # Disable preemption (can't be scheduled out)
    'raw_spin_lock',            # Real spinlock — stays non-sleeping on RT,
    'raw_spin_lock_irqsave',    #   but disables preemption, so you still
    'raw_spin_lock_irq',        #   can't call anything that sleeps.
    'bit_spin_lock',            # Calls preempt_disable, leaves it disabled on return
}

# ─── "Hazmat suit OFF" functions ─────────────────────────────────────────────
# These re-enable preemption/IRQs — the suit comes off.
ENABLE_FNS = {
    'local_irq_restore', 'local_irq_enable',
    'raw_local_irq_enable',
    'preempt_enable', 'sched_preempt_enable_no_resched',
    'preempt_enable_no_resched',
    'raw_spin_unlock', 'raw_spin_unlock_irqrestore', 'raw_spin_unlock_irq',
}

# ─── "Nap" functions — these SLEEP on PREEMPT_RT ─────────────────────────────
# Metaphor: calling these is like saying "wake me up when ready."
#           You can't do this while wearing the hazmat suit!
SPIN_LOCK_FNS = {'spin_lock', 'spin_lock_bh'}

# Memory allocators — on RT, even GFP_ATOMIC allocations can sleep
# because the internal SLUB locks become rt_mutex.
ALLOC_FNS = {
    'kmalloc', 'kzalloc', 'kcalloc', 'kmalloc_node', 'kzalloc_node',
    '__kmalloc', '__kmalloc_node',
    'kmem_cache_alloc', 'kmem_cache_alloc_node',
    'krealloc', 'kvmalloc', 'kvzalloc',
}

# folio/page locking — unconditionally calls might_sleep()
FOLIO_LOCK_FNS = {
    'folio_lock', 'lock_page', 'folio_lock_killable',
    'folio_lock_or_retry', '__folio_lock', 'lock_page_killable',
}

# Combined: all functions that sleep on RT
SLEEP_FNS = SPIN_LOCK_FNS | ALLOC_FNS | FOLIO_LOCK_FNS

# ─── RT-capable architectures ────────────────────────────────────────────────
# Only these select ARCH_SUPPORTS_RT in their Kconfig.
RT_ARCHS = {'arm', 'arm64', 'loongarch', 'riscv', 'x86'}

# ─── Annotation macros (not real function calls) ─────────────────────────────
ANNOTATION_MACROS = {
    '__acquires', '__releases', '__acquires_shared', '__releases_shared',
    '__acquires_ctx_lock', '__releases_ctx_lock',
    '__must_hold', '__lockfunc',
    # Iteration macros — tree-sitter misparsing creates spurious call edges
    'list_for_each_entry', 'list_for_each_entry_safe',
    'list_for_each_entry_reverse', 'list_for_each_entry_rcu',
    'hlist_for_each_entry', 'hlist_for_each_entry_safe',
    'hlist_for_each_entry_rcu',
}

# ─── Functions excluded from disabler propagation ────────────────────────────
# These become sleeping on RT or are internal infrastructure — not real disablers.
RT_SLEEPING_WRAPPERS = {
    'write_lock', 'read_lock', 'write_lock_irq', 'read_lock_irq',
    'write_lock_bh', 'read_lock_bh', 'write_lock_irqsave',
    'read_lock_irqsave', 'spin_lock', 'spin_lock_irq',
    'spin_lock_bh', 'spin_lock_irqsave',
    '_raw_spin_lock', '_raw_spin_lock_irq', '_raw_spin_lock_irqsave',
    'write_unlock', 'read_unlock', 'write_unlock_irq', 'read_unlock_irq',
    'write_unlock_bh', 'read_unlock_bh', 'write_unlock_irqrestore',
    'read_unlock_irqrestore',
    'spin_unlock', 'spin_unlock_irq', 'spin_unlock_bh',
    'spin_unlock_irqrestore',
    'rt_write_unlock', 'rt_read_unlock', 'rwbase_write_unlock',
    'rwbase_read_unlock',
    'rcu_read_lock', '__rcu_read_lock',
    'schedule', '__schedule_loop', '__schedule', 'preempt_schedule',
    'schedule_timeout', 'schedule_preempt_disabled',
    'finish_wait', '__finish_wait',
    'ww_acquire_init',
}

# ─── False positive filters ──────────────────────────────────────────────────
FP_PATH_PREFIXES = ('tools/testing/',)
FP_PANIC_FUNCS = {
    'oops_end', 'panic', 'crash_kexec', '__crash_kexec',
    'machine_real_restart', 'machine_restart', 'machine_halt',
    'emergency_restart',
}
FP_BALANCED_DISABLERS = {
    'fpu__init_check_bugs',
    'el0_svc', 'el0_da', 'el0_ia', 'el0_fpac', 'el0_sys',
    'cbc_decrypt', 'cbc_encrypt',
}
FP_NOOP_64BIT = {
    'u64_stats_update_begin_irqsave', '__u64_stats_irqsave',
}


# ═══════════════════════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════════════════════

def strip_ansi(s):
    """Remove terminal color codes from semcode output."""
    return re.sub(r'\x1b\[[0-9;]*m', '', s)


def semcode_cmd(db_path, commands):
    """Run semcode interactive commands and return stdout."""
    semcode_bin = os.environ.get('SEMCODE', None)
    if not semcode_bin:
        # Try common locations
        for candidate in ['semcode',
                          os.path.expanduser('~/semcode/target/release/semcode'),
                          '/usr/local/bin/semcode']:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                semcode_bin = candidate
                break
            # Check PATH
            from shutil import which
            found = which(candidate)
            if found:
                semcode_bin = found
                break
    if not semcode_bin:
        print("Error: 'semcode' not found. Set SEMCODE env var or add it to PATH.",
              file=sys.stderr)
        sys.exit(1)

    r = subprocess.run(
        [semcode_bin, '--database', db_path],
        input='\n'.join(commands) + '\nquit\n',
        capture_output=True, text=True
    )
    return r.stdout


def load_call_graph(db_path):
    """
    Load the kernel call graph from semcode's function dump.

    Metaphor: This is the "phone book" — who calls whom in the entire kernel.
    We ask semcode to dump all functions with their callees as JSON.

    Returns: (call_graph dict, func_files dict, raw functions list)
    """
    dump_path = '/tmp/semcode_rt_detect.json'
    print("# Loading call graph from semcode...", file=sys.stderr)
    semcode_cmd(db_path, [f'df {dump_path}'])

    with open(dump_path) as f:
        functions = json.load(f)
    os.unlink(dump_path)

    call_graph = {}
    func_files = {}

    for fn in functions:
        calls = fn.get('calls')
        if not calls:
            continue
        name = fn['name']
        file_path = fn.get('file_path', '')
        # Skip non-RT architectures at load time
        if file_path.startswith('arch/'):
            arch = file_path.split('/')[1]
            if arch not in RT_ARCHS:
                continue
        call_graph[name] = set(calls) - ANNOTATION_MACROS
        func_files[name] = file_path

    print(f"#   {len(call_graph)} functions in call graph", file=sys.stderr)
    return call_graph, func_files, functions


def fetch_bodies(db_path, func_names):
    """
    Fetch function bodies from semcode for ordering verification.

    We need the actual source code to check: does the disable happen
    BEFORE the sleep call? (ordering matters — suit on, THEN nap = bug)
    """
    commands = [f'func -v {name}' for name in func_names]
    raw = semcode_cmd(db_path, commands)

    bodies = {}
    current_func = None
    body_lines = []
    capturing = False

    for line in raw.splitlines():
        clean = strip_ansi(line)
        m = re.match(r"Name:\s+(\w+)", clean)
        if m:
            if current_func and body_lines:
                bodies[current_func] = body_lines
            current_func = m.group(1)
            body_lines = []
            capturing = False
            continue
        if 'Function Definition:' in clean:
            capturing = True
            continue
        if capturing and clean.startswith('─'):
            continue
        if capturing:
            if clean.startswith('=== ') or 'Callers' in clean or 'Callees' in clean:
                capturing = False
                continue
            body_lines.append(clean)

    if current_func and body_lines:
        bodies[current_func] = body_lines
    return bodies


def is_false_positive(func_name, file_path, disable_fn):
    """Apply false positive filters."""
    if file_path.startswith('arch/'):
        arch = file_path.split('/')[1]
        if arch not in RT_ARCHS:
            return True
    if any(file_path.startswith(p) for p in FP_PATH_PREFIXES):
        return True
    if func_name in FP_PANIC_FUNCS:
        return True
    if disable_fn in FP_BALANCED_DISABLERS:
        return True
    if disable_fn in FP_NOOP_64BIT:
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# DIRECT detection
# ═══════════════════════════════════════════════════════════════════════════════

def detect_direct(call_graph, func_files, db_path):
    """
    Detect DIRECT atomic sleep violations.

    Pattern: A single function calls BOTH a disable function AND a sleep function,
    with the disable happening first and no enable in between.

    Metaphor: The worker puts on the hazmat suit, then tries to nap —
              all within the same task (function).

    Example (drivers/md/raid5-ppl.c):
        local_irq_save(flags);          // hazmat suit ON
        spin_lock(&log->io_list_lock);  // tries to nap — BUG on RT!
    """
    print("\n# ═══ DIRECT detection ═══", file=sys.stderr)

    # ─── Step 1: Find suspects ────────────────────────────────────────────
    # Functions that call BOTH a disable function AND a sleep function.
    suspects = []
    for name, callees in call_graph.items():
        disables = callees & DISABLE_FNS
        sleeps = callees & SPIN_LOCK_FNS  # Direct only checks spin_lock
        if disables and sleeps:
            suspects.append({
                'name': name,
                'file': func_files.get(name, ''),
            })

    print(f"#   {len(suspects)} suspects", file=sys.stderr)

    # ─── Step 2: Fetch bodies and check ordering ──────────────────────────
    bodies = fetch_bodies(db_path, [s['name'] for s in suspects])

    disable_re = re.compile(
        r'\b(' + '|'.join(re.escape(f) for f in DISABLE_FNS) + r')\s*\('
    )
    spin_re = re.compile(
        r'(?<![_a-zA-Z])(' + '|'.join(re.escape(f) for f in SPIN_LOCK_FNS) + r')\s*\('
    )
    enable_re = re.compile(
        r'\b(' + '|'.join(re.escape(f) for f in ENABLE_FNS) + r')\s*\('
    )

    # ─── Step 3: Report ───────────────────────────────────────────────────
    results = []
    for s in sorted(suspects, key=lambda x: x['file']):
        lines = bodies.get(s['name'], [])
        if not lines:
            continue

        disable_idx = None
        disable_text = None

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            # Find "hazmat suit on"
            if disable_idx is None and disable_re.search(line):
                disable_idx = i
                disable_text = line.strip()
            # Check if suit comes OFF before the nap
            if disable_idx is not None and enable_re.search(line):
                disable_idx = None
                disable_text = None
                continue
            # Find "nap attempt" while suit is on
            if disable_idx is not None and spin_re.search(line):
                if not is_false_positive(s['name'], s['file'], ''):
                    results.append({
                        'file': s['file'],
                        'func': s['name'],
                        'disable_text': disable_text,
                        'sleep_text': line.strip(),
                    })
                break

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# INDIRECT detection
# ═══════════════════════════════════════════════════════════════════════════════

def build_transitive_sets(call_graph, max_depth):
    """
    Build transitive disabler and sleeper sets.

    Metaphor: Find all the "middle managers" — functions that don't directly
    put on the hazmat suit, but delegate to someone who does (and doesn't
    take it off). These are the indirect disablers.

    KEY INSIGHT: Only flag b() as a disabler if it does NOT also call the
    corresponding enable. If b() calls preempt_disable() AND preempt_enable(),
    it's balanced — the caller is NOT left in atomic context.
    """
    # Find direct disablers/enablers
    direct_disablers = set()
    direct_enablers = set()
    for name, callees in call_graph.items():
        if callees & DISABLE_FNS:
            direct_disablers.add(name)
        if callees & ENABLE_FNS:
            direct_enablers.add(name)

    # "Unbalanced disablers" = call disable but NOT enable
    unbalanced_direct = direct_disablers - direct_enablers

    # Direct sleepers
    direct_sleepers = set()
    for name, callees in call_graph.items():
        if callees & SLEEP_FNS:
            direct_sleepers.add(name)

    # Propagate transitively up to max_depth
    disablers = set(unbalanced_direct)
    sleepers = set(direct_sleepers)
    enablers = set(direct_enablers)

    for d in range(2, max_depth + 1):
        new_disablers = set()
        new_sleepers = set()
        new_enablers = set()
        for name, callees in call_graph.items():
            if name in RT_SLEEPING_WRAPPERS:
                continue
            if name not in enablers and (callees & enablers):
                new_enablers.add(name)
            # Indirect disabler: calls a disabler, doesn't call any enabler
            if name not in disablers and (callees & disablers):
                if not (callees & enablers):
                    new_disablers.add(name)
            if name not in sleepers and (callees & sleepers):
                if name not in {'spin_lock_irqsave', 'spin_lock_irq',
                                '_raw_spin_lock_irqsave', '_raw_spin_lock_irq'}:
                    new_sleepers.add(name)
        enablers.update(new_enablers)
        disablers.update(new_disablers)
        sleepers.update(new_sleepers)

    # Only indirect (exclude direct — caught by direct detection)
    indirect_disablers = disablers - unbalanced_direct

    return indirect_disablers, sleepers, direct_disablers


def reaches_target(call_graph, func, targets, depth, visited=None):
    """
    Check if func transitively calls any target within depth levels.
    Returns the call chain if found, else None.

    Metaphor: Trace the delegation chain — who told whom to put on the suit?
    """
    if visited is None:
        visited = set()
    if func in visited:
        return None
    visited.add(func)
    callees = call_graph.get(func, set())
    hit = callees & targets
    if hit:
        return [func, next(iter(hit))]
    if depth <= 1:
        return None
    for callee in callees:
        chain = reaches_target(call_graph, callee, targets, depth - 1, visited)
        if chain:
            return [func] + chain
    return None


def detect_indirect(call_graph, func_files, db_path, max_depth):
    """
    Detect INDIRECT atomic sleep violations.

    Pattern: Function a() calls b() which disables preempt/IRQ (and doesn't
    re-enable), then a() calls c() which eventually sleeps.

    Metaphor: The manager (a) tells one worker (b) to put on the hazmat suit
    for everyone, then tells another worker (c) to take a nap. The suit is
    still on when the nap happens!

    Example (fs/gfs2/quota.c — confirmed bug):
        gfs2_quota_init() {
            spin_lock_bucket(hash);     // → hlist_bl_lock → bit_spin_lock → preempt_disable
            gfs2_glock_put(qd->qd_gl); // → ... → spin_lock (sleeps on RT!)
        }
    """
    print("\n# ═══ INDIRECT detection ═══", file=sys.stderr)

    # ─── Step 1: Build transitive disabler/sleeper sets ───────────────────
    print(f"#   Building transitive sets (depth={max_depth})...", file=sys.stderr)
    indirect_disablers, sleepers, direct_disablers = \
        build_transitive_sets(call_graph, max_depth)
    print(f"#   Indirect disablers: {len(indirect_disablers)}", file=sys.stderr)
    print(f"#   Indirect sleepers: {len(sleepers)}", file=sys.stderr)

    # ─── Step 2: Find suspects ────────────────────────────────────────────
    # Functions that call BOTH an indirect disabler AND a sleeper.
    suspects = []
    for name, callees in call_graph.items():
        if name in direct_disablers:
            continue  # Already caught by direct detection
        disable_callees = callees & indirect_disablers
        sleep_callees = callees & sleepers
        if disable_callees and sleep_callees:
            suspects.append({
                'name': name,
                'file': func_files.get(name, ''),
                'disabler': disable_callees,
                'sleeper': sleep_callees,
            })

    print(f"#   {len(suspects)} suspects", file=sys.stderr)

    # ─── Step 3: Fetch bodies and check ordering ──────────────────────────
    bodies = fetch_bodies(db_path, [s['name'] for s in suspects])

    # ─── Step 4: Verify ordering and report ───────────────────────────────
    results = []
    for s in sorted(suspects, key=lambda x: x['file']):
        lines = bodies.get(s['name'], [])
        if not lines:
            continue

        disable_callees = s['disabler']
        sleep_callees = s['sleeper']
        disable_idx = None
        sleep_idx = None
        disable_fn = None
        sleep_fn = None

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if disable_idx is None:
                for df in disable_callees:
                    if re.search(r'\b' + re.escape(df) + r'\s*\(', line):
                        disable_idx = i
                        disable_fn = df
                        break
            if disable_idx is not None and sleep_idx is None:
                for sf in sleep_callees:
                    if re.search(r'\b' + re.escape(sf) + r'\s*\(', line):
                        sleep_idx = i
                        sleep_fn = sf
                        break
            if disable_idx is not None and sleep_idx is not None:
                break

        if disable_idx is not None and sleep_idx is not None and sleep_idx > disable_idx:
            if is_false_positive(s['name'], s['file'], disable_fn):
                continue

            d_chain = reaches_target(call_graph, disable_fn, DISABLE_FNS, max_depth)
            s_chain = reaches_target(call_graph, sleep_fn, SLEEP_FNS, max_depth)

            results.append({
                'file': s['file'],
                'func': s['name'],
                'disable_text': lines[disable_idx].strip(),
                'sleep_text': lines[sleep_idx].strip(),
                'disable_chain': ' → '.join(d_chain) if d_chain else disable_fn,
                'sleep_chain': ' → '.join(s_chain) if s_chain else sleep_fn,
            })

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# Main — orchestrate and report
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    kernel_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    db_path = os.path.join(kernel_dir, '.semcode.db')
    max_depth = 3
    mode = 'all'

    for i, arg in enumerate(sys.argv):
        if arg == '--database' and i + 1 < len(sys.argv):
            db_path = sys.argv[i + 1]
        if arg == '--depth' and i + 1 < len(sys.argv):
            max_depth = int(sys.argv[i + 1])
        if arg == '--mode' and i + 1 < len(sys.argv):
            mode = sys.argv[i + 1]

    if not os.path.isdir(db_path):
        print(f"Error: database not found at {db_path}", file=sys.stderr)
        print("Run: semcode-index -s <kernel_dir>", file=sys.stderr)
        sys.exit(1)

    # Load the call graph once — shared by both detection modes
    call_graph, func_files, _ = load_call_graph(db_path)

    # ─── Run detection ────────────────────────────────────────────────────
    direct_results = []
    indirect_results = []

    if mode in ('direct', 'all'):
        direct_results = detect_direct(call_graph, func_files, db_path)

    if mode in ('indirect', 'all'):
        indirect_results = detect_indirect(call_graph, func_files, db_path, max_depth)

    # ─── Print report ─────────────────────────────────────────────────────
    print("")
    print("# ═══════════════════════════════════════════════════════════════")
    print("# PREEMPT_RT Potential Atomic Sleep Violations")
    print("# ═══════════════════════════════════════════════════════════════")

    if direct_results:
        print("")
        print(f"## DIRECT violations ({len(direct_results)})")
        print("## Pattern: disable() ... sleep() in the same function")
        print("")
        for r in direct_results:
            print(f"{r['file']}:{r['func']}():")
            print(f"  {r['disable_text']}")
            print(f"  -> {r['sleep_text']}  [sleeps on PREEMPT_RT]")
            print("")

    if indirect_results:
        print("")
        print(f"## INDIRECT violations ({len(indirect_results)})")
        print("## Pattern: call_disabler() ... call_sleeper() via call chain")
        print("")
        for r in indirect_results:
            print(f"{r['file']}:{r['func']}():")
            print(f"  {r['disable_text']}")
            print(f"    chain: {r['disable_chain']}")
            print(f"  -> {r['sleep_text']}")
            print(f"    chain: {r['sleep_chain']}")
            print("")

    total = len(direct_results) + len(indirect_results)
    print(f"# Total: {total} (direct: {len(direct_results)}, indirect: {len(indirect_results)})")


if __name__ == '__main__':
    main()
