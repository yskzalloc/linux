.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests: rust_ffi_contract
==========================================

FFI contract violation detection: ffi_alloc_buf() returns 0 but leaves
alloc->buffer NULL, and ffi_check_result() receives that NULL. ``alloc`` is
a pointer, recorded as the address it holds, so the violation shows in the
returns: 0 from ffi_alloc_buf(), -EFAULT from the checker, for the same
object at both boundaries. The test checks those, the scalar arguments
(256, 16, 1), and through DWARF that ``alloc`` points at a ``struct
ffi_alloc { buffer, data_size, free_async, flags }`` -- whose fields are
not read.
Opted in with ``KCOV_DATAFLOW_rust_ffi_contract.o := y``::

  ./test_modules.py -t rust_ffi_contract
  ./trigger-view.py rust_ffi_contract -C 8
