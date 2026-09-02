.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: eight_struct_args_rust
===============================================

Rust equivalent of eight_struct_args_c (rsf_*, rstf_*, rstpf_* with
``#[no_mangle]``), built only with CONFIG_RUST=y. Opted in with
``KCOV_DATAFLOW_eight_struct_args_rust.o := y``::

  ./test_modules.py -t eight_struct_args_rust
  ./trigger-view.py eight_struct_args_rust --raw

Object returns
--------------

``rsf_ret_struct()`` returns ``S4`` (``#[repr(C)]``, 4 * u64 = 32 bytes) by
value from an ``extern "C"`` function, so it takes the same indirect return
path as the C module's ``sf_ret_struct()``: the ABI hands the callee a
caller-provided buffer, and trace-ret reports that buffer as an object --
one value word per field, the address they were read from in word [2] of
the record, and ``size`` the whole 32 bytes::

  [RET  ] seq=... rsf_ret_struct+0x.. ret(32) @0xffff888000003000 = {0x11, 0x11, 0x22, 0x33}

Same operands and therefore same expected fields as the C side, which is
the point of having both: ``v1 = S1 { a: 0x11 }`` and
``v2 = S2 { a: 0x11, b: 0x22 }`` give
``S4 { a: (*a).a, b: (*b).a, c: (*b).b, d: (*a).a + (*b).b }``.
test_modules.py asserts all four fields, the object size and the non-zero
object address for both modules through one shared expectation.

Note that ``#[repr(C)]`` is what makes the field offsets the compiler
reports match the C layout. A default-repr Rust struct may be reordered,
and the reported offsets would then describe that layout instead -- still
correct, but not comparable with the C module field by field.
