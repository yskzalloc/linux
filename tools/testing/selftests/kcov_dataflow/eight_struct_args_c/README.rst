.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: eight_struct_args_c
============================================

C module with 1-8 struct pointer arguments (flat s1..s8), value-nested
st1..st8 and pointer-linked stp1..stp8 towers (on stack, kmalloc and
vmalloc), pointer forwarding and a struct return value. Opted in with
``KCOV_DATAFLOW_eight_struct_args_c.o := y``; writing
``/sys/kernel/debug/kcov_dataflow_test/trigger_struct`` runs it::

  ./test_modules.py -t eight_struct_args_c
  ./trigger-view.py eight_struct_args_c --raw

What is recorded is decided by the IR alone: an argument index is the IR
position, a pointer is recorded as the address it holds -- a plain C
pointer says nothing about how much of its pointee may be read, so none of
it is -- and an object returned in memory is read, one value word per
element of its IR type. Which parameter and which member a record holds
comes from the module's DWARF, through ``sancov -symbolize-dataflow``.

Pointer arguments
-----------------

``sf_N(struct s1 *a, ..., struct sN *h)`` is called with the same stack
objects ``v1`` .. ``v8`` every time. test_modules.py checks that:

- every sf_N records IR arguments 0 .. N-1, each as a value: one value
  word, no object address, 8 bytes, not NULL;
- argument k is the same pointer ``&v(k+1)`` in every sf_N, and the eight
  pointers are distinct;
- ``sf_fwd()`` and ``sf_fwd_inner()``, which it forwards to, receive the
  same ``&v1`` .. ``&v4``;
- every sf_N, stf_N and stpf_N returns the sum of what it reads, and
  stpf_8 runs twice (kmalloc and vmalloc).

Through DWARF, each sf_N record names its parameter (``a`` .. ``h``) and the
pointee type ``struct sK`` with its members ``a``, ``b``, ... at 64-bit
steps -- their layout, not their values, every member ``"observed": false``
with ``bytes_read`` 0 (rust_ffi_contract shows a C parameter whose pointee
is recorded: declared ``alloc[static 1]``)::

  [ENTRY] seq=... sf_3+0x36 [eight_struct_args_c] arg[0](8) = 0xffff88800558fd38  <- a=0xffff88800558fd38 -> s1 {a} (not read)

Object returns
--------------

``sf_ret_struct()`` returns ``struct s4`` by value. That is 4 * u64 = 32
bytes, over the register-return limit on both x86-64 and arm64, so the ABI
returns it indirectly through a caller-provided buffer, and trace-ret
reports that buffer as an object: one value word per element of its IR
type, ``%struct.s4 = { i64, i64, i64, i64 }``, word [2] of the record
holding the address they were read from, and ``size`` the whole object::

  [RET  ] seq=... sf_ret_struct+0x.. ret(32) @0xffff88800558f8c8 = {0x11, 0x11, 0x22, 0x33}  <- {.a=0x11, .b=0x11, .c=0x22, .d=0x33}

The fields follow from ``v1 = {0x11}`` and ``v2 = {0x11, 0x22}``:
``{.a = a->a, .b = b->a, .c = b->b, .d = a->a + b->b}``. test_modules.py
asserts all four, the object size, and that word [2] is non-zero -- a
scalar return leaves it zero, so that is what tells the two modes apart.
Through DWARF the four words are the members ``a``, ``b``, ``c``, ``d`` of
``struct s4``, at bits 0, 64, 128 and 192.

The buffer is passed as a hidden struct-return pointer, IR argument 0,
which trace-args does not record: ``a`` and ``b`` are IR arguments 1 and 2,
``&v1`` and ``&v2``, and their descriptors carry the ``hidden_args`` flag.

A struct small enough to come back in registers (<= 16 bytes here) has no
address to report from, so it arrives as the value, or as one record per
element of a first-class aggregate. That path is covered by the LLVM IR
tests rather than here; the ``__sancov_dataflow`` descriptor of each call
says which element a record is.
