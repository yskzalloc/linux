#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
test_modules.py - run the kcov_dataflow test modules, one KTAP test each.

Every module is loaded, triggered with recording active and unloaded by
trigger-view.py's run_capture(). The records that belong to the module are
then compared with the values its trigger function passes and returns, so a
test passes only when the instrumented arguments, the fields of objects
returned in memory and the return values came back intact through the
kcov_dataflow buffer. The module's call tree is echoed as KTAP diagnostics.

What is recorded is decided by the IR alone: an argument index is the IR
position, a pointer is recorded as the address it holds, and only an object
passed or returned in memory (byval, sret) is read field by field. Which
source parameter, and which struct member, a record holds comes from the
module's DWARF instead, through "sancov -symbolize-dataflow"; when sancov is
found ($SANCOV, --sancov or PATH) every record is also checked against that
mapping.

    ./test_modules.py                 # all modules
    ./test_modules.py -t rust_ffi_contract -C 8 --vmlinux vmlinux

Modules that were not built (no CONFIG_RUST, no toolchain) are reported as
SKIP; a kernel without /sys/kernel/debug/kcov_dataflow skips everything.
"""
import argparse
import contextlib
import importlib.util
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "kselftest"))
import ksft  # noqa: E402


def _load_trigger_view():
    spec = importlib.util.spec_from_file_location(
        "trigger_view", os.path.join(HERE, "trigger-view.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tv = _load_trigger_view()


class Check:
    """Collects expectation failures for one module."""

    def __init__(self):
        self.failures = []

    def eq(self, what, got, want):
        if got != want:
            self.failures.append(f"{what}: got {fmt(got)}, want {fmt(want)}")

    def true(self, what, cond):
        if not cond:
            self.failures.append(what)


def fmt(v):
    if isinstance(v, list):
        return "[" + ", ".join(fmt(x) for x in v) + "]"
    if isinstance(v, int):
        return f"0x{v:x}"
    return str(v)


def entries(cap, recs, func):
    return [r for r in recs if r["type"] == tv.DF_TYPE_ENTRY and func in cap.funcs(r)]


def ret_recs(cap, recs, func):
    """Every RET record of @func, whole, so structured returns stay visible."""
    return [r for r in recs if r["type"] == tv.DF_TYPE_RET and func in cap.funcs(r)]


def rets(cap, recs, func):
    """
    The scalar return values of @func.

    vals[0] only, which is the whole value for a register-returned scalar and
    just the first field of a structured return -- use ret_recs() for those.
    """
    return [r["val"] for r in ret_recs(cap, recs, func)]


def flat_sum(n):
    """sf_n() returns a->a + b->b + ... over s1..sn: 0x11 + 0x22 + ..."""
    return sum(0x11 * k for k in range(1, n + 1))


def nested_sum(n, _memo={}):
    """
    stf_n()/stpf_n() return field0 (0x11 * n) plus the recursive sums of the
    embedded st1..st(n-1); the same values are used for the value-nested and
    the pointer-linked towers.
    """
    if n not in _memo:
        _memo[n] = 0x11 * n + sum(nested_sum(k) for k in range(1, n))
    return _memo[n]


def check_struct_family(cap, recs, c, p, flat_ns, stpf8_runs):
    """
    Shared expectations for eight_struct_args_c (p="") and
    eight_struct_args_rust (p="r"): @flat_ns are the sf_N called by the
    trigger, @stpf8_runs how often the pointer-linked tower is walked.
    """
    # The trigger passes the same objects v1..v8 to every sf_N, so arg k of
    # each is the same pointer, &v(k+1). A plain pointer -- C's struct s1 *,
    # Rust's *const S1 -- is recorded as its value, and its pointee is not
    # read: the IR says nothing about how much of it may be. One value word,
    # no object address.
    ptrs = pointer_args(cap, recs, c, f"{p}sf_{max(flat_ns)}", max(flat_ns))
    c.eq(f"{p}sf_N: the {len(ptrs)} objects are distinct",
         len(set(ptrs.values())), len(ptrs))
    for n in flat_ns:
        ents = entries(cap, recs, f"{p}sf_{n}")
        c.true(f"{p}sf_{n}: ENTRY records", bool(ents))
        c.eq(f"{p}sf_{n} ENTRY arg indexes",
             sorted({r["arg_idx"] for r in ents}), list(range(n)))
        # rustc's merge-functions may alias rsf_1 with rstf_1, which is
        # called with another object: require &v1 among the values there.
        aliased = p and n == 1
        for k in range(n):
            got = pointer_args_of(c, f"{p}sf_{n} arg[{k}]", ents, k)
            if k not in ptrs:
                continue
            if aliased:
                c.true(f"{p}sf_{n} arg[{k}] is &v{k + 1} (0x{ptrs[k]:x}) "
                       f"among {fmt(got)}", ptrs[k] in got)
            else:
                c.eq(f"{p}sf_{n} arg[{k}] is &v{k + 1}", got,
                     [ptrs[k]] * len(got))
        # rustc may alias identical bodies (rsf_1 == rstf_1), so the RET
        # list can carry the alias's calls too: check every value.
        got = rets(cap, recs, f"{p}sf_{n}")
        c.true(f"{p}sf_{n} RET values all {fmt(flat_sum(n))}: {fmt(got)}",
               bool(got) and all(v == flat_sum(n) for v in got))

    for fam, calls in ((f"{p}stf", 1), (f"{p}stpf", stpf8_runs)):
        for n in range(1, 9):
            got = rets(cap, recs, f"{fam}_{n}")
            c.true(f"{fam}_{n}: RET records", bool(got))
            c.true(f"{fam}_{n} RET values all {fmt(nested_sum(n))}: {fmt(got)}",
                   all(v == nested_sum(n) for v in got))
        c.eq(f"{fam}_8 RET count", len(rets(cap, recs, f"{fam}_8")), calls)

    for f in (f"{p}sf_fwd", f"{p}sf_fwd_inner"):
        c.eq(f"{f} RET", rets(cap, recs, f), [flat_sum(4)])
        # sf_fwd passes its pointers on unchanged, so both see &v1..&v4.
        ents = entries(cap, recs, f)
        for k in range(4):
            got = pointer_args_of(c, f"{f} arg[{k}]", ents, k)
            if k in ptrs:
                c.eq(f"{f} arg[{k}] is &v{k + 1}", got, [ptrs[k]] * len(got))

    # sf_ret_struct(&v1, &v2) returns, by value,
    #   struct s4 { .a = a->a, .b = b->a, .c = b->b, .d = a->a + b->b }
    # from v1 = {0x11} and v2 = {0x11, 0x22}. struct s4 is 4 * u64 = 32 bytes,
    # which exceeds the register-return limit on both x86-64 and arm64, so the
    # ABI returns it indirectly through a caller-provided buffer and trace-ret
    # reports that buffer as an object: nvals == 4 field words, word [2] the
    # address they were read from, size the whole object. Assert all of that --
    # checking only vals[0] passes just as happily for a scalar return, which
    # is what this test used to do.
    #
    # The buffer is passed as a hidden struct-return pointer, IR argument 0,
    # which trace-args does not record; a and b keep their IR positions, 1
    # and 2. The buffer's address is in the RET record instead.
    f = f"{p}sf_ret_struct"
    ents = entries(cap, recs, f)
    c.true(f"{f}: ENTRY records", bool(ents))
    c.eq(f"{f} ENTRY arg indexes (0 is the sret pointer)",
         sorted({r["arg_idx"] for r in ents}), [1, 2])
    for k, v in ((1, 0), (2, 1)):
        got = pointer_args_of(c, f"{f} arg[{k}]", ents, k)
        if v in ptrs:
            c.eq(f"{f} arg[{k}] is &v{v + 1}", got, [ptrs[v]] * len(got))

    # The fields read are the elements of the buffer's IR type. clang gives
    # it %struct.s4 = { i64, i64, i64, i64 }: four fields. rustc gives
    # sret([32 x i8]), one opaque 32-byte field, which the compiler describes
    # in 8-byte pieces, as it does any field wider than a value word: four
    # words again, the same bytes. (Before it did, only .a was read.)
    want = [0x11, 0x11, 0x22, 0x33]
    got = ret_recs(cap, recs, f)
    c.true(f"{f}: RET record", bool(got))
    for r in got:
        c.eq(f"{f} RET fields (the IR type's elements)", r["vals"], want)
        c.eq(f"{f} RET size (whole struct s4)", r["size"], 4 * 8)
        # num_fields > 0 is the object-address mode; the kernel then stores the
        # address it read the fields from in word [2]. A scalar return leaves
        # it zero, so a non-zero value here is what distinguishes the two.
        c.true(f"{f} RET carries an object address, not a value "
               f"(addr=0x{r['addr']:x})", r["addr"] != 0 and r["mem"])
        c.true(f"{f} RET fields were readable (no KCOV_DF_MAGIC_BAD)",
               tv.MAGIC_BAD not in r["vals"])


def pointer_args_of(c, what, ents, k):
    """
    The values of the ENTRY records in @ents for IR argument @k, each checked
    to be a pointer recorded as a value: one value word, no object address,
    8 bytes, not NULL.
    """
    got = []
    recs = [r for r in ents if r["arg_idx"] == k]
    c.true(f"{what}: ENTRY record", bool(recs))
    for r in recs:
        c.true(f"{what} recorded as a value (nvals {len(r['vals'])}, "
               f"addr 0x{r['addr']:x}, size {r['size']})",
               len(r["vals"]) == 1 and r["addr"] == 0 and r["size"] == 8
               and not r["mem"])
        c.true(f"{what} is a non-NULL pointer", r["val"] not in (0, tv.MAGIC_BAD))
        got.append(r["val"])
    return got


def snapshot_args_of(c, what, ents, k, size):
    """
    (pointer, value words) of the ENTRY records in @ents for IR argument @k,
    each checked to be a pointer recorded with a snapshot of the @size bytes
    behind it -- what the compiler's IR says are dereferenceable: the values
    read in memory, word [2] the pointer, one word per 8 bytes.
    """
    got = []
    recs = [r for r in ents if r["arg_idx"] == k]
    c.true(f"{what}: ENTRY record", bool(recs))
    for r in recs:
        c.true(f"{what} recorded with a {size}-byte pointee snapshot (mem "
               f"{r['mem']}, nvals {len(r['vals'])}, size {r['size']})",
               r["mem"] and r["size"] == size and
               len(r["vals"]) == (size + 7) // 8)
        c.true(f"{what} is a non-NULL pointer", r["addr"] != 0)
        c.true(f"{what}: snapshot readable (no KCOV_DF_MAGIC_BAD)",
               tv.MAGIC_BAD not in r["vals"])
        got.append((r["addr"], r["vals"]))
    return got


def pointer_args(cap, recs, c, func, n):
    """{k: value} of the pointer arguments 0..@n-1 of the first call of @func."""
    ents = entries(cap, recs, func)
    ptrs = {}
    for k in range(n):
        got = pointer_args_of(c, f"{func} arg[{k}]", ents, k)
        if got:
            ptrs[k] = got[0]
    return ptrs


def check_eight_struct_args_c(cap, recs, c):
    check_struct_family(cap, recs, c, "", range(1, 9), stpf8_runs=2)


def check_eight_struct_args_rust(cap, recs, c):
    check_struct_family(cap, recs, c, "r", (1, 2, 4, 8), stpf8_runs=1)


def check_rust_ffi_contract(cap, recs, c):
    """
    ffi_alloc_buf(&alloc = {NULL, 0, 0, 0}, 256, 16, is_async=1) records
    data_size + offsets_size and returns 0 without filling alloc->buffer;
    ffi_check_result() then finds the buffer NULL and returns -EFAULT.

    alloc is passed by pointer, which is recorded as the address it holds:
    the violated contract shows in the return values at both boundaries,
    and in both functions receiving the same object. ffi_alloc_buf() takes
    a plain struct ffi_alloc *, so its fields are not read there;
    ffi_check_result() takes struct ffi_alloc alloc[static 1], which makes
    the IR dereferenceable(24), so the kernel records the 24 bytes behind
    it: { buffer = NULL, data_size = 256 + 16, free_async = 0, flags = 0 }
    -- the NULL buffer of the violated contract, in the record itself.
    """
    ents = entries(cap, recs, "ffi_alloc_buf")
    by_arg = {r["arg_idx"]: r for r in ents}
    c.eq("ffi_alloc_buf ENTRY arg indexes", sorted(by_arg), [0, 1, 2, 3])
    alloc = pointer_args_of(c, "ffi_alloc_buf arg[0] &alloc", ents, 0)
    if 1 in by_arg:
        c.eq("ffi_alloc_buf arg[1] data_size", by_arg[1]["val"], 256)
    if 2 in by_arg:
        c.eq("ffi_alloc_buf arg[2] offsets_size", by_arg[2]["val"], 16)
    if 3 in by_arg:
        c.eq("ffi_alloc_buf arg[3] is_async", by_arg[3]["val"], 1)
        c.eq("ffi_alloc_buf arg[3] is_async size (int)", by_arg[3]["size"], 4)
    c.eq("ffi_alloc_buf RET (claims success)", rets(cap, recs, "ffi_alloc_buf"), [0])

    ents = entries(cap, recs, "ffi_check_result")
    c.true("ffi_check_result: ENTRY record", bool(ents))
    got = snapshot_args_of(c, "ffi_check_result arg[0] &alloc", ents, 0, 24)
    if alloc:
        c.eq("ffi_check_result arg[0] is the object ffi_alloc_buf filled in",
             [a for a, _ in got], alloc[:1] * len(got))
    for _, vals in got:
        # buffer, data_size, then free_async and flags in one word.
        c.eq("ffi_check_result arg[0] *alloc as ffi_alloc_buf left it",
             vals, [0, 256 + 16, 0])
    got = rets(cap, recs, "ffi_check_result")
    c.true(f"ffi_check_result RET -EFAULT: {fmt(got)}",
           len(got) == 1 and got[0] & 0xffffffff == 0xfffffff2)


def check_rust_kworker_remote(cap, recs, c):
    """
    The trigger only queues a work item and waits; the records come from the
    kworker that called kcov_df_remote_start(REMOTE_HANDLE). All three phases
    of CompositeStore must show up (v0-mangled names keep the method names).
    """
    c.true("records captured from the kworker", bool(recs))
    names = set().union(*(cap.funcs(r) for r in recs)) if recs else set()
    for phase in ("populate", "update", "drain"):
        c.true(f"CompositeStore::{phase} recorded",
               any("CompositeStore" in n and phase in n for n in names))

    # Each phase takes &mut self, which rustc makes dereferenceable(24): the
    # three RBTree roots behind it are recorded with the pointer. The trees
    # are empty when populate() starts, and filled when update() and drain()
    # do.
    for phase, empty in (("populate", True), ("update", False),
                         ("drain", False)):
        func = composite_store_method(cap, recs, phase)
        if not func:
            continue
        got = snapshot_args_of(c, f"CompositeStore::{phase} arg[0] self",
                               entries(cap, recs, func), 0, 24)
        for _, roots in got:
            if empty:
                c.eq(f"CompositeStore::{phase} self: empty tree roots",
                     roots, [0, 0, 0])
            else:
                c.true(f"CompositeStore::{phase} self: filled tree roots "
                       f"{fmt(roots)}", all(roots))


def composite_store_method(cap, recs, phase):
    """The kallsyms name of CompositeStore::@phase, or None."""
    for r in recs:
        for n in cap.funcs(r):
            if "CompositeStore" in n and phase in n:
                return n
    return None


# --- DWARF: which source parameter, and which member, each record holds ---
#
# The records themselves carry IR facts only. sancov -symbolize-dataflow
# joins each call site's __sancov_dataflow descriptor with the
# DW_TAG_LLVM_sancov_observation the compiler emitted for it, which is how a
# consumer names what was recorded. These checks verify that join: every
# module record is found, agrees with its descriptor, resolves exactly, and
# the test functions' parameters, struct members and pointee layouts are the
# ones the source declares.


class Dwarf:
    """Records of one capture joined with the module's sancov source map."""

    def __init__(self, cap, smap):
        self.cap = cap
        self.smap = smap

    def point(self, rec):
        tgt = self.cap.binary_addr(rec)
        if not tgt or tgt[0] != self.cap.ko_path:
            return None
        return self.smap.lookup(tgt[1])


def check_dwarf_records(cap, recs, c, dw):
    """Every module record agrees with the descriptor and DWARF of its call."""
    stats = {"records": 0, "exact": 0, "positional": 0, "objects": 0,
             "pointees": 0, "snapshots": 0}
    for r in recs:
        stats["records"] += 1
        p = dw.point(r)
        name = "/".join(sorted(cap.funcs(r))) or f"0x{r['pc']:x}"
        what = f"{name} {'RET' if r['type'] == tv.DF_TYPE_RET else 'arg[%d]' % r['arg_idx']}"
        if not p:
            c.true(f"DWARF: {what}: no sancov point for its pc", False)
            continue
        kind = "ret" if r["type"] == tv.DF_TYPE_RET else "args"
        c.eq(f"DWARF: {what}: call site kind", p["kind"], kind)
        obs = p.get("observation") or {}
        if kind == "args":
            c.eq(f"DWARF: {what}: descriptor IR argument", obs.get("ir_arg"),
                 r["arg_idx"])
        # A record of values read in memory read an object, or the bytes
        # behind a pointer the IR says are dereferenceable; the descriptor
        # must say the call reports one of those, and which.
        snapshot = "pointee" in obs.get("flags", [])
        c.eq(f"DWARF: {what}: descriptor says object or pointee snapshot",
             obs.get("class") == "object" or snapshot, r["mem"])
        if snapshot:
            c.eq(f"DWARF: {what}: a pointee snapshot is of a pointer",
                 obs.get("class"), "pointer")
        if obs.get("class") != "object":
            c.eq(f"DWARF: {what}: descriptor size", min(obs.get("size", 0), 255),
                 r["size"])
        src = p.get("source") or {}
        if src.get("provenance") == "exact":
            stats["exact"] += 1
        elif "unused" in obs.get("flags", []) and src.get("provenance") == "heuristic":
            # The optimizer drops the debug records of a parameter the
            # function does not use, so the source map has no entry for it;
            # sancov then guesses by position, and says so.
            stats["positional"] += 1
        else:
            c.true(f"DWARF: {what}: resolved exactly ({src.get('summary')})", False)
        stats["objects"] += obs.get("class") == "object"
        stats["pointees"] += bool(src.get("pointee"))
        stats["snapshots"] += bool((src.get("pointee") or {}).get("bytes_read"))
    return stats


def check_param(c, dw, what, rec, name, number, pointee=None, members=None,
                bytes_read=0):
    """
    The record holds source parameter @name (1-based @number), a pointer to
    @pointee with @members if given, @bytes_read of which were recorded.
    """
    p = dw.point(rec)
    src = (p or {}).get("source") or {}
    par = src.get("parameter") or {}
    c.eq(f"DWARF: {what}: source parameter", (par.get("name"), par.get("number")),
         (name, number))
    if pointee is not None:
        pt = src.get("pointee") or {}
        c.true(f"DWARF: {what}: pointee type {pt.get('type')!r} names {pointee!r}",
               pointee in str(pt.get("type")))
        c.eq(f"DWARF: {what}: pointee members",
             [(f["name"], f["bit_offset"]) for f in pt.get("fields", [])], members)
        c.eq(f"DWARF: {what}: pointee bytes read", pt.get("bytes_read"),
             bytes_read)
        # Every member within the bytes read is observed, every one beyond
        # them, or of a pointee that was not read, is not.
        for f in pt.get("fields", []):
            inside = f["bit_offset"] + f["bit_size"] <= 8 * bytes_read
            c.eq(f"DWARF: {what}: pointee member {f['name']} observed",
                 f.get("observed", True), inside)


def dwarf_struct_family(cap, recs, c, dw, p, flat_ns):
    names = "abcdefgh"
    for n in flat_ns:
        for r in entries(cap, recs, f"{p}sf_{n}"):
            k = r["arg_idx"]
            if p and n == 1 and "S1" not in str(((dw.point(r) or {}).get("source") or {}).get("type")):
                continue        # rsf_1 aliased with rstf_1
            # sf_N(struct s1 *a, ..., struct sN *h): the pointee layout is
            # the struct's, member j at bit 64 * j -- the fields a consumer
            # would name, were they read. A plain pointer: none are.
            check_param(c, dw, f"{p}sf_{n} arg[{k}]", r, names[k], k + 1,
                        pointee=f"{'S' if p else 's'}{k + 1}",
                        members=[(names[j], 64 * j) for j in range(k + 1)])

    f = f"{p}sf_ret_struct"
    for r in entries(cap, recs, f):
        # IR argument 0 is the hidden sret pointer: IR 1 and 2 are source
        # parameters 1 and 2.
        k = r["arg_idx"]
        if k in (1, 2):
            check_param(c, dw, f"{f} arg[{k}]", r, names[k - 1], k)
        flags = ((dw.point(r) or {}).get("observation") or {}).get("flags", [])
        c.true(f"DWARF: {f} arg[{k}]: descriptor flags hidden_args ({flags})",
               "hidden_args" in flags)
    for r in ret_recs(cap, recs, f):
        pt = dw.point(r) or {}
        flags = (pt.get("observation") or {}).get("flags", [])
        c.true(f"DWARF: {f} RET: descriptor flags sret_object ({flags})",
               "sret_object" in flags)
        fields = tv.source_fields(pt)
        c.eq(f"DWARF: {f} RET members", [(m["name"], m["bit_offset"]) for m in fields],
             [("a", 0), ("b", 64), ("c", 128), ("d", 192)])
        # The object's fields were read, and each value word is a member: as
        # clang lays out the IR type, one element per member, and as rustc's
        # opaque [32 x i8] is read, in 8-byte pieces that here are members.
        c.eq(f"DWARF: {f} RET: a value word per member", len(r["vals"]),
             len(fields))
        if len(fields) == len(r["vals"]):
            got = {m["name"]: v for m, v in zip(fields, r["vals"])}
            c.eq(f"DWARF: {f} RET by member", got,
                 {"a": 0x11, "b": 0x11, "c": 0x22, "d": 0x33})
            ksft.print_msg(f"DWARF: {f} {tv.describe(r, pt)}")


def dwarf_eight_struct_args_c(cap, recs, c, dw):
    dwarf_struct_family(cap, recs, c, dw, "", range(1, 9))


def dwarf_eight_struct_args_rust(cap, recs, c, dw):
    dwarf_struct_family(cap, recs, c, dw, "r", (1, 2, 4, 8))


def dwarf_rust_ffi_contract(cap, recs, c, dw):
    for r in entries(cap, recs, "ffi_alloc_buf"):
        k = r["arg_idx"]
        name = ("alloc", "data_size", "offsets_size", "is_async")[k] if k < 4 else "?"
        if k == 0:
            # The fields that show the violated contract: their names and
            # places are known from DWARF; a plain pointer, so their values
            # are not recorded here.
            check_param(c, dw, "ffi_alloc_buf arg[0]", r, "alloc", 1,
                        pointee="ffi_alloc",
                        members=[("buffer", 0), ("data_size", 64),
                                 ("free_async", 128), ("flags", 160)])
            ksft.print_msg(f"DWARF: ffi_alloc_buf {tv.describe(r, dw.point(r))}")
        else:
            check_param(c, dw, f"ffi_alloc_buf arg[{k}]", r, name, k + 1)
    for r in entries(cap, recs, "ffi_check_result"):
        # alloc[static 1]: all 24 bytes recorded, and DWARF cuts them into
        # the members, the NULL buffer among them.
        p = dw.point(r)
        check_param(c, dw, "ffi_check_result arg[0]", r, "alloc", 1,
                    pointee="ffi_alloc",
                    members=[("buffer", 0), ("data_size", 64),
                             ("free_async", 128), ("flags", 160)],
                    bytes_read=24)
        snap = tv.snapshot_bytes(r, p)
        if snap:
            c.eq("DWARF: ffi_check_result *alloc by member",
                 tv.bytes_members(*snap, p["source"]["pointee"]["fields"]),
                 [".buffer=0x0", ".data_size=0x110", ".free_async=0x0",
                  ".flags=0x0"])
        else:
            c.true("DWARF: ffi_check_result arg[0]: a snapshot record", False)
        ksft.print_msg(f"DWARF: ffi_check_result {tv.describe(r, p)}")


def dwarf_rust_kworker_remote(cap, recs, c, dw):
    """&mut self of CompositeStore: a 24-byte snapshot of three RBTrees."""
    for phase in ("populate", "update", "drain"):
        func = composite_store_method(cap, recs, phase)
        for r in entries(cap, recs, func) if func else []:
            if r["arg_idx"] != 0:
                continue
            p = dw.point(r)
            pt = ((p or {}).get("source") or {}).get("pointee") or {}
            c.true(f"DWARF: CompositeStore::{phase} self: pointee type "
                   f"{pt.get('type')!r}", "CompositeStore" in str(pt.get("type")))
            c.eq(f"DWARF: CompositeStore::{phase} self: pointee bytes read",
                 pt.get("bytes_read"), 24)
            # rustc may reorder the fields; the three roots fill 24 bytes.
            c.eq(f"DWARF: CompositeStore::{phase} self: members at",
                 sorted(f["bit_offset"] for f in pt.get("fields", [])),
                 [0, 64, 128])
            c.true(f"DWARF: CompositeStore::{phase} self: all members observed",
                   all(f.get("observed", True) for f in pt.get("fields", [])))
            ksft.print_msg(f"DWARF: CompositeStore::{phase} {tv.describe(r, p)}")


TESTS = (
    ("rust_ffi_contract", False, check_rust_ffi_contract, dwarf_rust_ffi_contract),
    ("eight_struct_args_c", False, check_eight_struct_args_c,
     dwarf_eight_struct_args_c),
    ("eight_struct_args_rust", False, check_eight_struct_args_rust,
     dwarf_eight_struct_args_rust),
    ("rust_kworker_remote", True, check_rust_kworker_remote,
     dwarf_rust_kworker_remote),
)


def diag_tree(cap, recs, vmlinux, smap=None):
    """The call tree, values named from the module's DWARF when @smap."""
    out = io.StringIO()
    smaps = {cap.ko_path: smap} if smap else None
    with contextlib.redirect_stdout(out):
        tv.print_tree(recs, cap.syms, vmlinux, {}, cap.ko_path,
                      cap.mod_text_start, cap, smaps)
    for line in out.getvalue().splitlines():
        ksft.print_msg(line)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("-t", "--test", action="append",
                        help="run only this module (repeatable)")
    parser.add_argument("-C", "--context", type=int, default=0,
                        help="echo N records before/after each module record")
    parser.add_argument("--vmlinux", help="vmlinux for addr2line and KASLR")
    parser.add_argument("--sancov", help="sancov for the DWARF checks "
                        "(default: $SANCOV, then PATH)")
    args = parser.parse_args()

    tests = [t for t in TESTS if not args.test or t[0] in args.test]
    ksft.print_header()
    ksft.set_plan(len(tests))

    skip_all = None
    if not os.path.exists(tv.KCOV_DF_PATH):
        skip_all = f"{tv.KCOV_DF_PATH} not available (CONFIG_KCOV_DATAFLOW_ARGS/RET)"
    elif os.geteuid() != 0:
        skip_all = "must run as root"

    vmlinux = tv.find_vmlinux(args.vmlinux)
    sancov = tv.find_sancov(args.sancov)
    if not sancov:
        ksft.print_msg("DWARF checks skipped: no sancov ($SANCOV, --sancov "
                       "or PATH)")
    for name, remote, check, dwarf_check in tests:
        if skip_all:
            ksft.test_result_skip(f"{name}: {skip_all}")
            continue
        ko = tv.find_module(name)
        if not ko:
            ksft.test_result_skip(f"{name}: {name}.ko not built")
            continue
        try:
            cap = tv.run_capture(ko, remote=remote, vmlinux=vmlinux,
                                 log=ksft.print_msg)
        except OSError as e:
            ksft.test_result_fail(f"{name}: {e}")
            continue

        recs = cap.module_records()
        ksft.print_msg(f"{name}: {cap.total_words} words, {len(cap.records)} "
                       f"records, {len(recs)} from {name} "
                       f"(kaslr_offset=0x{cap.kaslr_offset:x})")
        # Say so before the expectations are checked: a truncated run fails on
        # whatever the trigger called last, which looks nothing like "the
        # buffer was too small" unless it is spelled out.
        if cap.saturated:
            ksft.print_msg(f"{name}: WARNING: capture buffer full at "
                           f"{tv.BUF_SIZE} words; the end of the run was "
                           f"dropped, so later records are missing")
        c = Check()
        smap = None
        if sancov:
            try:
                smap = tv.SourceMap(ko, sancov)
            except (OSError, ValueError) as e:
                c.true(f"DWARF: {e}", False)
        diag_tree(cap, cap.context_records(args.context) if args.context
                  else recs, vmlinux, smap)

        check(cap, recs, c)
        if smap:
            dw = Dwarf(cap, smap)
            st = check_dwarf_records(cap, recs, c, dw)
            ksft.print_msg(f"{name}: DWARF: {st['records']} records, "
                           f"{st['exact']} resolved exactly, "
                           f"{st['positional']} unused ones by position, "
                           f"{st['objects']} objects read by member, "
                           f"{st['pointees']} pointers with a pointee "
                           f"layout, {st['snapshots']} of them with the "
                           f"bytes behind them recorded")
            if dwarf_check:
                dwarf_check(cap, recs, c, dw)
        for f in c.failures:
            ksft.print_msg(f"FAIL {name}: {f}")
        ksft.test_result(not c.failures, name)

    ksft.finished()


if __name__ == "__main__":
    main()
