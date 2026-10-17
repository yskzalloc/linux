.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests
=======================

Selftests for ``/sys/kernel/debug/kcov_dataflow`` (see
Documentation/dev-tools/kcov-dataflow.rst).

Layout
------

Makefile, Kbuild
    kselftest build: the C programs are built by lib.mk, the test modules
    (one directory each, listed in Kbuild) by kbuild against ``KDIR``.
user_ioctl/
    ioctl interface test (kselftest harness, TAP).
binderfs/
    binder ioctls under recording (TAP).
rust_ffi_contract/, eight_struct_args_c/, eight_struct_args_rust/,
rust_kworker_remote/
    test modules; each README.rst says what the module exercises.
test_modules.py
    KTAP runner: loads every module, triggers it with recording active and
    checks the captured arguments, the fields of objects returned in memory,
    the bytes recorded behind dereferenceable pointers and the return values
    against the values the module uses. With ``sancov`` (``$SANCOV``,
    ``--sancov`` or ``PATH``) it also resolves every record through the
    module's ``__sancov_dataflow`` descriptors and DWARF and checks the
    source parameters, struct members, pointee layouts and which pointee
    members a snapshot holds.
    Modules that are not built are SKIPped.
trigger-view.py
    Interactive viewer the runner is built on (call tree or ``--raw``
    records, kallsyms/addr2line symbolization, ``--remote`` capture). With
    ``sancov`` found, values are named after their source parameters and
    members, and a pointer shows what it points to: by member, cut out of
    the bytes recorded behind it where the compiler's IR said they may be
    read (``-> T {.m=v, ...}``), else its layout alone (``(not read)``);
    ``--dwarf`` extends that to vmlinux records, ``--no-dwarf`` turns it
    off.

Kernel
------

The kernel and the modules must be built with a clang that has the
trace-args/trace-ret passes (and, for the Rust modules, a rustc built
against that LLVM). The config fragment ``config`` lists what the tests
need; with virtme-ng::

    vng --build --config tools/testing/selftests/kcov_dataflow/config \
        LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC

Build
-----

From the kernel tree, with the same toolchain variables::

    make LLVM=1 headers
    make -C tools/testing/selftests TARGETS=kcov_dataflow \
        LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC

``KDIR`` defaults to the source tree; pass ``KDIR=<O dir>`` for out-of-tree
builds. The Rust modules are built only when ``KDIR/.config`` has
``CONFIG_RUST=y``. ``make ... install INSTALL_PATH=<dir>`` produces a
self-contained tree with ``run_kselftest.sh``.

Run
---

On the target (root, debugfs mounted)::

    vng --user root --exec \
        "tools/testing/selftests/kcov_dataflow/test_modules.py"
    tools/testing/selftests/kcov_dataflow/user_ioctl/user_ioctl
    tools/testing/selftests/kcov_dataflow/binderfs/binderfs_test

or, from an installed tree, ``run_kselftest.sh -c kcov_dataflow``.
``test_modules.py -t <module> -C 8`` runs one module and echoes eight
records of context around each module record; ``trigger-view.py <module>
[--raw] [-C N] [--remote] [--vmlinux vmlinux] [--dwarf | --no-dwarf]``
shows the capture without checking it::

  eight_struct_args_rust.rs:380     0x10ef = rstpf_8+0x2f(p=0xffff888002a9cc80 -> Stp8 {field0, ..., field7} (not read))
  eight_struct_args_rust.rs:485     {.a=0x11, .b=0x11, .c=0x22, .d=0x33} @0xffff888005f374e8 = rsf_ret_struct+0x3b(a=... -> S1 {a} (not read), b=... -> S2 {a, b} (not read))
  rust_ffi_contract.c:81            0xfffffff2 = ffi_check_result+0x28(alloc=0xffff888005f37d38 -> ffi_alloc {.buffer=0x0, .data_size=0x110, .free_async=0x0, .flags=0x0})
  rust_kworker_remote.rs:58         <rust_kworker_remote::CompositeStore>::populate+0x2f(self=0xffff8880019f7c20 -> CompositeStore {.primary.root.rb_node=0x0, .aux.root.rb_node=0x0, .scratch.root.rb_node=0x0})

What a record holds
-------------------

Records are IR facts: ``arg_idx`` is the IR argument, and a pointer is
recorded as the address it holds. Memory is read only where the IR says it
may be: an object passed or returned in memory (``byval``, ``sret``), one
value word per element of its IR type, an element wider than 8 bytes -- or
rustc's opaque ``[N x i8]`` -- in 8-byte pieces; and the first bytes behind
a pointer the IR says is ``dereferenceable(N)``, at most
``CONFIG_KCOV_DATAFLOW_POINTEE_BYTES``, as a raw snapshot. Rust's ``&T`` and
``&mut T`` are (``CompositeStore::populate``'s ``self``); a C pointer is
not, unless declared as an array of static size (``ffi_check_result``'s
``alloc[static 1]``), and neither is a Rust raw pointer (``rstpf_8``'s
``p``). Which source parameter, struct member or pointee member that is
comes from DWARF, offline: ``sancov -symbolize-dataflow <module>.ko``
reports it per call site, and a module record's pc, relative to the
module's ``.text``, is the address it reports.
