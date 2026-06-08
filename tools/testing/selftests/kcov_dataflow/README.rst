.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow Selftests
========================

This directory contains selftests for the KCOV-Dataflow subsystem
(``/sys/kernel/debug/kcov_dataflow``).

Prerequisites
-------------

Build the kernel with::

    CONFIG_KCOV=y
    CONFIG_KCOV_DATAFLOW_ARGS=y
    CONFIG_KCOV_DATAFLOW_RET=y
    CONFIG_DEBUG_INFO=y

Tests
-----

user_ioctl/user_ioctl.c
    Automated ioctl interface test (9 TAP cases)::

        make -C tools/testing/selftests/kcov_dataflow
        ./user_ioctl/user_ioctl

trigger-view.py
    Loads a test module via finit_module() with recording active,
    prints captured records with symbol resolution and source line numbers::

        python3 trigger-view.py <module_name>
        python3 trigger-view.py <module_name> --raw
        python3 trigger-view.py <module_name> --vmlinux vmlinux

rust_ffi_contract/
    Demonstrates FFI contract violation detection. A callee returns
    success but leaves buffer=NULL. kcov_dataflow captures struct
    fields proving the violation.
    Per-module opt-in: ``KCOV_DATAFLOW_rust_ffi_contract.o := y``::

        make LLVM=1 CC=clang M=tools/testing/selftests/kcov_dataflow/rust_ffi_contract modules
        python3 trigger-view.py rust_ffi_contract

rust_ffi_contract/
    Demonstrates FFI contract violation detection. A callee returns
    success but leaves buffer=NULL. kcov_dataflow captures struct
    fields proving the violation.
    Per-module opt-in: ``KCOV_DATAFLOW_rust_ffi_contract.o := y``::

        make LLVM=1 CC=clang M=tools/testing/selftests/kcov_dataflow/rust_ffi_contract modules
        python3 trigger-view.py rust_ffi_contract
