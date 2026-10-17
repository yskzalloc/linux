.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: rust_ffi_contract
==========================================

FFI contract violation detection: ffi_alloc_buf() returns 0 but leaves
alloc->buffer NULL, and ffi_check_result() receives that NULL. ``alloc`` is
a pointer, recorded as the address it holds, so the violation shows in the
returns: 0 from ffi_alloc_buf(), -EFAULT from the checker, for the same
object at both boundaries. The test checks those, the scalar arguments
(256, 16, 1), and through DWARF that ``alloc`` points at a ``struct
ffi_alloc { buffer, data_size, free_async, flags }``.

ffi_alloc_buf() takes a plain ``struct ffi_alloc *``, whose pointee is not
read. ffi_check_result() takes ``struct ffi_alloc alloc[static 1]``, which
tells the compiler a whole struct is there, so its IR is
``dereferenceable(24)`` and the record carries the 24 bytes behind the
pointer -- the violated contract itself, ``buffer`` NULL after success::

  rust_ffi_contract.c:54     0x0 = ffi_alloc_buf+0x3b(alloc=0xffff888005f37d38 -> ffi_alloc {buffer, data_size, free_async, flags} (not read), data_size=0x100, offsets_size=0x10, is_async=0x1)
  rust_ffi_contract.c:81     0xfffffff2 = ffi_check_result+0x28(alloc=0xffff888005f37d38 -> ffi_alloc {.buffer=0x0, .data_size=0x110, .free_async=0x0, .flags=0x0})

test_modules.py checks the three value words ``[0, 0x110, 0]`` and, through
DWARF, that they are those four members.
Opted in with ``KCOV_DATAFLOW_rust_ffi_contract.o := y``::

  ./test_modules.py -t rust_ffi_contract
  ./trigger-view.py rust_ffi_contract -C 8
