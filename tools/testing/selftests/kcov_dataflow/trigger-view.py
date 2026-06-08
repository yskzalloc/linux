#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
trigger-view.py - Load a module with kcov_dataflow
recording active, then pretty-print captured records.

Usage:
    python3 trigger-view.py eight_struct_args_c
    python3 trigger-view.py rust_ffi_contract
    python3 trigger-view.py eight_struct_args_c --raw

The script:
  1. Opens /sys/kernel/debug/kcov_dataflow
  2. Inits and mmaps the buffer
  3. Enables recording for this process
  4. Loads the module via finit_module() -- init runs in our context
  5. Disables recording
  6. Unloads the module
  7. Parses and prints captured records with kallsyms resolution
"""
import os
import sys
import struct
import ctypes
import ctypes.util
import argparse
import fcntl

# Constants
DF_TYPE_ENTRY = 0xE
DF_TYPE_RET = 0xF
MAGIC_BAD = 0xBADADD85
BUF_SIZE = 1048576  # 1M words = 8MB

# Ioctl numbers
def _IOR(t, nr, size):
    return (2 << 30) | (ord(t) << 8) | nr | (size << 16)

def _IO(t, nr):
    return (ord(t) << 8) | nr

KCOV_DF_INIT_TRACK = _IOR('d', 1, 8)
KCOV_DF_ENABLE = _IO('d', 100)
KCOV_DF_DISABLE = _IO('d', 101)

# syscall numbers (x86_64)
import platform
_machine = platform.machine()
if _machine == "aarch64":
    SYS_FINIT_MODULE = 273
    SYS_DELETE_MODULE = 106
else:  # x86_64
    SYS_FINIT_MODULE = 313
    SYS_DELETE_MODULE = 176

SELFTEST_DIR = os.path.dirname(os.path.abspath(__file__))


def load_kallsyms():
    """Load kernel symbols for PC resolution."""
    syms = []
    try:
        with open("/proc/kallsyms") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    addr = int(parts[0], 16)
                    name = parts[2]
                    mod = parts[3].strip("[]") if len(parts) > 3 else ""
                    syms.append((addr, name, mod))
    except (PermissionError, FileNotFoundError):
        pass
    syms.sort()
    return syms


def load_addr2line_cache(vmlinux=None):
    """Build addr2line resolver using vmlinux or module debug info."""
    import subprocess
    cache = {}
    # Find vmlinux
    if not vmlinux:
        for p in ["/boot/vmlinux", "vmlinux", "/usr/lib/debug/boot/vmlinux"]:
            if os.path.exists(p):
                vmlinux = p
                break
    if not vmlinux:
        return cache, None
    return cache, vmlinux


def resolve_line(pc, vmlinux, cache):
    """Resolve PC to source file:line using addr2line."""
    if pc in cache:
        return cache[pc]
    if not vmlinux:
        cache[pc] = ""
        return ""
    import subprocess
    try:
        r = subprocess.run(
            ["addr2line", "-e", vmlinux, f"0x{pc:x}"],
            capture_output=True, text=True, timeout=2)
        loc = r.stdout.strip()
        if loc and loc != "??:0" and loc != "??:?":
            # Shorten path: keep only filename:line
            if "/" in loc:
                loc = loc.rsplit("/", 1)[1]
            cache[pc] = loc
        else:
            cache[pc] = ""
    except (subprocess.TimeoutExpired, FileNotFoundError):
        cache[pc] = ""
    return cache[pc]


def get_kernel_meta():
    """Collect kernel build metadata."""
    meta = {}
    try:
        with open("/proc/version") as f:
            meta["version"] = f.read().strip()
    except: pass
    try:
        import subprocess
        r = subprocess.run(["uname", "-r"], capture_output=True, text=True)
        meta["release"] = r.stdout.strip()
    except: pass
    # Try to get git SHA from kernel version string
    try:
        with open("/proc/version") as f:
            v = f.read()
            # Extract compiler version
            if "gcc" in v.lower():
                meta["compiler"] = v.split("(")[1].split(")")[0] if "(" in v else ""
            elif "clang" in v.lower():
                idx = v.lower().find("clang")
                meta["compiler"] = v[idx:idx+30].split(")")[0]
    except: pass
    return meta


def print_kernel_meta(meta, position="start"):
    """Print kernel metadata header/footer."""
    print(f"# {'─' * 60}")
    if position == "start":
        print(f"# Kernel: {meta.get('release', 'unknown')}")
        print(f"# Build:  {meta.get('version', 'unknown')[:80]}")
        if meta.get('compiler'):
            print(f"# Compiler: {meta['compiler']}")
    print(f"# {'─' * 60}")


def symbolize(pc, syms):
    """Find nearest symbol <= pc. Returns (display_name, module_tag)."""
    if not syms:
        return f"0x{pc:x}", ""
    lo, hi = 0, len(syms) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if syms[mid][0] <= pc:
            lo = mid
        else:
            hi = mid - 1
    addr, name, mod = syms[lo]
    if addr > pc:
        return f"0x{pc:x}", ""
    offset = pc - addr
    display = f"{name}+0x{offset:x}" if offset else name
    return display, f" [{mod}]" if mod else ""


def format_val(v):
    """Format a captured value."""
    if v == MAGIC_BAD:
        return "FAULT"
    if v == 0:
        return "0x0"
    return f"0x{v:x}"


def find_module(name):
    """Find the .ko file for the given test name."""
    ko_path = os.path.join(SELFTEST_DIR, name, f"{name}_mod.ko")
    if os.path.exists(ko_path):
        return ko_path
    # Try without _mod suffix
    ko_path = os.path.join(SELFTEST_DIR, name, f"{name}.ko")
    if os.path.exists(ko_path):
        return ko_path
    # Search for any .ko in the directory
    mod_dir = os.path.join(SELFTEST_DIR, name)
    if os.path.isdir(mod_dir):
        for f in os.listdir(mod_dir):
            if f.endswith(".ko"):
                return os.path.join(mod_dir, f)
    return None


def finit_module(ko_path):
    """Load a kernel module via finit_module syscall."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    fd = os.open(ko_path, os.O_RDONLY)
    ret = libc.syscall(SYS_FINIT_MODULE, fd, b"", 0)
    os.close(fd)
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"finit_module({ko_path}): {os.strerror(errno)}")


def delete_module(name):
    """Unload a kernel module."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    ret = libc.syscall(SYS_DELETE_MODULE, name.encode(), 0)
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"delete_module({name}): {os.strerror(errno)}")


def parse_records(buf, total_words):
    """Parse the ring buffer into a list of records."""
    records = []
    pos = 1
    while pos + 3 <= total_words and pos < BUF_SIZE:
        hdr = buf[pos]

        # Valid headers fit in 32 bits (upper 32 must be zero)
        if hdr >> 32:
            pos += 1
            continue

        rtype = (hdr >> 28) & 0xF

        if rtype not in (DF_TYPE_ENTRY, DF_TYPE_RET):
            pos += 1
            continue

        pc = buf[pos + 1]
        meta = buf[pos + 2]
        seq = hdr & 0x00FFFFFF
        num_vals = (hdr >> 24) & 0xF
        if num_vals == 0:
            num_vals = 1

        # Valid records always have a non-zero PC (kernel text address)
        if pc == 0:
            pos += 1
            continue

        val = buf[pos + 3] if pos + 3 < BUF_SIZE else 0
        vals = []
        for vi in range(num_vals):
            if pos + 3 + vi < BUF_SIZE:
                vals.append(int(buf[pos + 3 + vi]))
            else:
                vals.append(0)
        records.append({
            "type": rtype,
            "seq": seq,
            "pc": pc,
            "meta": meta,
            "val": val,
            "vals": vals,
        })
        pos += 3 + num_vals
    return records


def print_raw(records, syms, vmlinux=None, cache=None):
    """Print records in raw format with source line on left."""
    if cache is None:
        cache = {}
    for r in records:
        name, mod = symbolize(r["pc"], syms)
        sym = f"{name}{mod}"
        t = "ENTRY" if r["type"] == DF_TYPE_ENTRY else "RET  "
        arg_idx = (r["meta"] >> 56) & 0xFF
        size = (r["meta"] >> 48) & 0xFF
        loc = resolve_line(r["pc"], vmlinux, cache)
        left = f"{loc:>20s}" if loc else f"{'':>20s}"
        print(f"{left} │ [{t}] seq={r['seq']:3d} {sym} "
              f"arg[{arg_idx}]({size}) = {format_val(r['val'])}")


def print_tree(records, syms, vmlinux=None, cache=None):
    """Print records as indented call tree with source line on left."""
    if cache is None:
        cache = {}
    depth = 0
    call_stack = []  # Stack of (name, mod, args_str, pc) for matching returns
    i = 0
    while i < len(records):
        r = records[i]
        name, mod = symbolize(r["pc"], syms)

        if r["type"] == DF_TYPE_ENTRY:
            # Collect all args for this call (same PC, consecutive entries)
            args = []
            pc = r["pc"]
            while i < len(records) and records[i]["type"] == DF_TYPE_ENTRY \
                    and records[i]["pc"] == pc:
                vals = records[i]["vals"]
                if len(vals) > 1:
                    fields = ", ".join(format_val(v) for v in vals)
                    args.append("{" + fields + "}")
                else:
                    args.append(format_val(records[i]["val"]))
                i += 1
            args_str = ", ".join(args)
            call_stack.append((name, mod, args_str, pc))
            depth += 1
        else:
            # Pop void calls (no return record) until we find matching PC
            while call_stack and call_stack[-1][3] != r["pc"]:
                depth = max(0, depth - 1)
                indent = "  " * depth
                vname, vmod, vargs, vpc = call_stack.pop()
                loc = resolve_line(vpc, vmlinux, cache)
                left = f"{loc:>20s}" if loc else f"{'':>20s}"
                print(f"{left} │ {indent}{vname}({vargs}){vmod}")
            depth = max(0, depth - 1)
            indent = "  " * depth
            ret_size = (r["meta"] >> 48) & 0xFF
            loc = resolve_line(r["pc"], vmlinux, cache)
            left = f"{loc:>20s}" if loc else f"{'':>20s}"
            if call_stack:
                cname, cmod, cargs, _ = call_stack.pop()
                if ret_size == 0:
                    print(f"{left} │ {indent}{cname}({cargs}){cmod}")
                else:
                    print(f"{left} │ {indent}{format_val(r['val'])} = {cname}({cargs}){cmod}")
            else:
                if ret_size == 0:
                    print(f"{left} │ {indent}{name}(){mod}")
                else:
                    print(f"{left} │ {indent}{format_val(r['val'])} = {name}(){mod}")
            i += 1

    # Flush remaining void calls on the stack
    while call_stack:
        depth = max(0, depth - 1)
        indent = "  " * depth
        vname, vmod, vargs, vpc = call_stack.pop()
        loc = resolve_line(vpc, vmlinux, cache)
        left = f"{loc:>20s}" if loc else f"{'':>20s}"
        print(f"{left} │ {indent}{vname}({vargs}){vmod}")


def main():
    parser = argparse.ArgumentParser(
        description="Load a test module with kcov_dataflow and view records")
    parser.add_argument("module", help="Test module name (e.g. eight_struct_args_c)")
    parser.add_argument("--raw", action="store_true",
                        help="Print raw records instead of tree")
    parser.add_argument("--ko", help="Explicit path to .ko file")
    parser.add_argument("--context", "-C", type=int, default=0,
                        help="Show N lines before/after each module record")
    parser.add_argument("--vmlinux", help="Path to vmlinux for addr2line")
    args = parser.parse_args()

    # Find module
    if args.ko:
        ko_path = args.ko
    else:
        ko_path = find_module(args.module)
    if not ko_path or not os.path.exists(ko_path):
        print(f"Cannot find module for '{args.module}'", file=sys.stderr)
        print(f"Build it first: make LLVM=1 CC=clang "
              f"M=tools/testing/selftests/kcov_dataflow/{args.module} modules",
              file=sys.stderr)
        sys.exit(1)

    # Open kcov_dataflow
    # Ensure kallsyms shows real addresses
    try:
        with open("/proc/sys/kernel/kptr_restrict", "w") as f:
            f.write("0")
    except (PermissionError, FileNotFoundError):
        pass

    try:
        df_fd = os.open("/sys/kernel/debug/kcov_dataflow", os.O_RDWR)
    except OSError as e:
        print(f"Cannot open kcov_dataflow: {e}", file=sys.stderr)
        sys.exit(1)

    # Init + mmap
    fcntl.ioctl(df_fd, KCOV_DF_INIT_TRACK, BUF_SIZE)
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, ctypes.c_long
    ]
    buf_ptr = libc.mmap(None, BUF_SIZE * 8, 0x3, 0x01, df_fd, 0)
    if buf_ptr == ctypes.c_void_p(-1).value:
        print("mmap failed", file=sys.stderr)
        sys.exit(1)
    buf = (ctypes.c_uint64 * BUF_SIZE).from_address(buf_ptr)

    # Load module first (generates noise with INSTRUMENT_ALL)
    mod_name = os.path.basename(ko_path).replace(".ko", "")
    try:
        finit_module(ko_path)
        print(f"# Loaded {mod_name}")
    except OSError as e:
        print(f"Failed to load module: {e}", file=sys.stderr)
        sys.exit(1)

    # Get module .text address for PC filtering
    mod_text_start = 0
    try:
        with open(f"/sys/module/{mod_name}/sections/.text") as f:
            mod_text_start = int(f.read().strip(), 16)
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Enable recording AFTER load, BEFORE trigger (avoids VFS/loader noise)
    fcntl.ioctl(df_fd, KCOV_DF_ENABLE, 0)
    buf[0] = 0

    # Trigger the module's debugfs file to invoke test functions
    trigger_paths = [
        f"/sys/kernel/debug/kcov_dataflow_test/trigger",
        f"/sys/kernel/debug/kcov_dataflow_test/rust_ffi_trigger",
        f"/sys/kernel/debug/kcov_dataflow_test/trigger_struct",
        f"/sys/kernel/debug/kcov_dataflow_test/trigger_struct_rust",
        f"/sys/kernel/debug/trigger_rust",
        f"/sys/kernel/debug/trigger_struct_rust",
        f"/sys/kernel/debug/{mod_name}/trigger",
    ]
    for tp in trigger_paths:
        # Open WITHOUT O_CREAT: these trigger files are created by the loaded
        # module, never by us. Python's "w" mode implies O_CREAT, which — for a
        # wrong-name path whose parent debugfs dir DOES exist (e.g. trying
        # ".../kcov_dataflow_test/trigger" while the module made "trigger_struct")
        # — makes the kernel attempt to create a file in a debugfs directory that
        # has no ->create inode op, returning EOPNOTSUPP (errno 95) instead of a
        # clean ENOENT. Catch OSError broadly so any such non-matching path just
        # falls through to the module's real trigger file.
        try:
            fd = os.open(tp, os.O_WRONLY)
        except OSError:
            continue
        try:
            os.write(fd, b"1")
        finally:
            os.close(fd)
        break

    fcntl.ioctl(df_fd, KCOV_DF_DISABLE, 0)

    # Read kallsyms while module is still loaded (symbols available)
    syms = load_kallsyms()

    # Unload
    try:
        delete_module(mod_name)
    except OSError:
        pass

    # Parse and display
    total = int(buf[0])
    print(f"# Captured {total} words")
    records = parse_records(buf, total)
    print(f"# {len(records)} records")

    # Filter to module records using kallsyms
    # Build set of module symbol addresses for fast lookup
    mod_syms = set()
    for addr, name, mod in syms:
        if mod == mod_name and addr != 0:
            mod_syms.add(addr)

    def is_module_pc(pc):
        """Check if PC belongs to mod_name via kallsyms."""
        if mod_syms:
            # Binary search: find nearest symbol <= pc, check module
            lo, hi = 0, len(syms) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if syms[mid][0] <= pc:
                    lo = mid
                else:
                    hi = mid - 1
            return syms[lo][2] == mod_name
        # Fallback: if no module symbols (kptr_restrict), use .text start
        return mod_text_start and pc >= mod_text_start

    if syms or mod_text_start:
        if args.context > 0:
            module_indices = set()
            for i, r in enumerate(records):
                if is_module_pc(r["pc"]):
                    for j in range(max(0, i - args.context),
                                   min(len(records), i + args.context + 1)):
                        module_indices.add(j)
            records = [records[i] for i in sorted(module_indices)]
            print(f"# showing {len(records)} records with context={args.context} "
                  f"around {mod_name}\n")
        else:
            module_records = [r for r in records if is_module_pc(r["pc"])]
            print(f"# {len(module_records)} from {mod_name}\n")
            records = module_records
    else:
        print("")

    # Kernel metadata
    meta = get_kernel_meta()
    print_kernel_meta(meta, "start")

    # addr2line setup
    a2l_cache, vmlinux = load_addr2line_cache(args.vmlinux)

    if args.raw:
        print_raw(records, syms, vmlinux, a2l_cache)
    else:
        print_tree(records, syms, vmlinux, a2l_cache)

    print_kernel_meta(meta, "end")
    os.close(df_fd)


if __name__ == "__main__":
    main()
