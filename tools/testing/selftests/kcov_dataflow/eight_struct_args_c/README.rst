.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: eight_struct_args_c
============================================

C module with 1-8 struct pointer arguments (flat s1..s8), value-nested
st1..st8 and pointer-linked stp1..stp8 towers (on stack, kmalloc and
vmalloc), pointer forwarding and a struct return value. Opted in with
``KCOV_DATAFLOW_eight_struct_args_c.o := y``; test_modules.py checks the
expanded fields (0x11, 0x22, ...) and every return value::

  ./test_modules.py -t eight_struct_args_c
  ./trigger-view.py eight_struct_args_c --raw

Object returns
--------------

``sf_ret_struct()`` returns ``struct s4`` by value. That is 4 * u64 = 32
bytes, over the register-return limit on both x86-64 and arm64, so the ABI
returns it indirectly through a caller-provided buffer -- and trace-ret
reports that buffer the same way it reports a struct argument: one value
word per field, with word [2] of the record holding the address the fields
were read from, and ``size`` the whole object rather than one field::

  [RET  ] seq=... sf_ret_struct+0x91 ret(32) @0xffff888000003000 = {0x11, 0x11, 0x22, 0x33}

The fields follow from ``v1 = {0x11}`` and ``v2 = {0x11, 0x22}``:
``{.a = a->a, .b = b->a, .c = b->b, .d = a->a + b->b}``. test_modules.py
asserts all four, the object size, and that word [2] is non-zero -- a
scalar return leaves it zero, so that is what tells the two modes apart.
Checking only the first value word would pass equally for a scalar return,
which is what this test did before.

A struct small enough to come back in registers (<= 16 bytes here) has no
address to report from, so it arrives as one record per register piece with
no field table. That path is covered by the LLVM IR tests rather than here;
the piece records carry no piece index, so a consumer cannot tell two
pieces of one return from two calls to the same function.
