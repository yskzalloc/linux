.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: eight_struct_args_rust
===============================================

Rust equivalent of eight_struct_args_c (rsf_*, rstf_*, rstpf_* with
``#[no_mangle]``, ``extern "C"`` and ``#[repr(C)]`` structs), built only with
CONFIG_RUST=y. Opted in with ``KCOV_DATAFLOW_eight_struct_args_rust.o := y``;
writing ``/sys/kernel/debug/kcov_dataflow_test/trigger_struct_rust`` runs
it::

  ./test_modules.py -t eight_struct_args_rust
  ./trigger-view.py eight_struct_args_rust --raw --dwarf

As in the C module, what is recorded is decided by the IR alone, and which
parameter and member a record holds comes from DWARF, through ``sancov
-symbolize-dataflow``.

Pointer arguments
-----------------

``rsf_N(a: *const S1, ..., h: *const SN)`` is called for N = 1, 2, 4 and 8
with the same stack objects ``v1`` .. ``v8``, and is checked as in the C
module: IR arguments 0 .. N-1, each recorded as an 8-byte value, argument k
the same pointer ``&v(k+1)`` everywhere, ``rsf_fwd()`` and
``rsf_fwd_inner()`` receiving ``&v1`` .. ``&v4``, and every return value.
The pointer-linked tower is built once, with ``KBox``.

rustc's merge-functions may make identical bodies share one address -- the
one-field ``rsf_1`` and ``rstf_1`` -- so records of ``rstf_1``, called with
another object, can land under ``rsf_1``. For ``rsf_1`` test_modules.py
therefore requires ``&v1`` among the values rather than as the only one, and
skips its DWARF check when the merged body is ``rstf_1``'s.

Through DWARF, each record names its parameter (``a`` .. ``h``) and the
pointee ``S1`` .. ``S8`` with its members ``a``, ``b``, ... at 64-bit steps.
``#[repr(C)]`` is what gives those members the C layout.

Object returns
--------------

``rsf_ret_struct()`` returns ``S4`` (4 * u64 = 32 bytes) by value, so it takes
the same indirect return path as the C module's ``sf_ret_struct()``: the ABI
hands the callee a caller-provided buffer through a hidden struct-return
pointer, IR argument 0, which is not recorded -- ``a`` and ``b`` are IR
arguments 1 and 2 -- and trace-ret reports that buffer as an object, with the
address it was read from in word [2] of the record and ``size`` the whole 32
bytes.

Unlike clang, rustc types the buffer ``sret([32 x i8])``: an IR type with one
32-byte element, not four ``i64`` members. What is read is one value word per
IR element, and a value word holds the first 8 bytes of one, so the record
carries ``.a`` alone::

  [RET  ] seq=... rsf_ret_struct+0x.. ret(32) @0xffff8880389474d8 = 0x11

DWARF still describes ``S4 { a, b, c, d }``, but the IR type the
instrumentation goes by does not, so ``b``, ``c`` and ``d`` are not read.
test_modules.py asserts exactly that -- the object size, the non-zero object
address and the one word -- and checks the four members through DWARF; with
one value word for four members it reports them as not read one by one,
rather than naming the word.
