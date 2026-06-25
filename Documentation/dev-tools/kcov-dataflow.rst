.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow: function argument and return value extraction
=============================================================

KCOV-Dataflow captures function arguments and return values, including
automatic struct field decomposition, at instrumented kernel function
boundaries. It provides per-task, lock-free ring buffers accessible via
``mmap()``, enabling data-flow-aware fuzzing and post-mortem contract
verification.

Unlike KCOV's ``trace-pc`` which reports *which* code executed,
KCOV-Dataflow reports *what values* were passed and returned. This is
a completely separate device from ``/sys/kernel/debug/kcov``.

Prerequisites
-------------

KCOV-Dataflow requires Clang/LLVM with the ``trace-args`` and
``trace-ret`` SanitizerCoverage extensions. Standard (unpatched)
compilers will not expose these Kconfig options.

To enable KCOV-Dataflow, configure the kernel with::

        CONFIG_KCOV=y
        CONFIG_KCOV_DATAFLOW_ARGS=y
        CONFIG_KCOV_DATAFLOW_RET=y

Optional: instrument the entire kernel (significant overhead)::

        CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL=y

Coverage data becomes accessible once debugfs is mounted::

        mount -t debugfs none /sys/kernel/debug

Per-module instrumentation
--------------------------

To instrument a specific module, add to its Makefile::

        KCOV_DATAFLOW_my_module.o := y

For example, to instrument the Android binder driver::

        # drivers/android/Makefile
        KCOV_DATAFLOW_binder.o := y
        KCOV_DATAFLOW_binder_alloc.o := y

To instrument an entire directory, set the variable without a filename::

        # fs/Makefile
        KCOV_DATAFLOW := y

The build system automatically adds the required compiler flags
(``-fsanitize-coverage=trace-args,trace-ret``). Debug info is provided
by ``CONFIG_DEBUG_INFO`` which is a Kconfig dependency.

Data collection
---------------

The following program demonstrates how to collect function argument and
return value data for a single syscall:

.. code-block:: c

    #include <stdio.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <sys/types.h>
    #include <sys/ioctl.h>
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>

    #define KCOV_DF_INIT_TRACE  _IOR('d', 1, unsigned long)
    #define KCOV_DF_ENABLE      _IO('d', 100)
    #define KCOV_DF_DISABLE     _IO('d', 101)
    #define BUF_SIZE            (1 << 20)  /* 1M words = 8MB */

    int main(void)
    {
        int fd;
        uint64_t *buf, n, i;

        fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
        if (fd == -1)
            perror("open"), exit(1);

        /* Allocate buffer (size in u64 words). */
        if (ioctl(fd, KCOV_DF_INIT_TRACE, BUF_SIZE))
            perror("ioctl(INIT)"), exit(1);

        /* Map the buffer into user space. */
        buf = (uint64_t *)mmap(NULL, BUF_SIZE * sizeof(uint64_t),
                               PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (buf == MAP_FAILED)
            perror("mmap"), exit(1);

        /* Enable data-flow collection for this task. */
        if (ioctl(fd, KCOV_DF_ENABLE, 0))
            perror("ioctl(ENABLE)"), exit(1);

        /* Reset counter. */
        __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

        /* === Trigger syscall(s) here === */
        read(-1, NULL, 0);

        /* Read how many words were written. */
        n = __atomic_load_n(&buf[0], __ATOMIC_RELAXED);

        /* Parse TLV records. */
        i = 1;
        while (i + 3 < n) {
            uint64_t type_seq = buf[i];
            uint64_t pc       = buf[i + 1];
            uint64_t meta     = buf[i + 2];
            uint32_t type     = (type_seq >> 28) & 0xF;
            uint32_t num_vals = (type_seq >> 24) & 0xF;
            uint32_t seq      = type_seq & 0x00FFFFFF;
            uint32_t arg_idx  = (meta >> 56) & 0xFF;
            uint32_t size     = (meta >> 48) & 0xFF;

            if (type_seq >> 32 || (type != 0xE && type != 0xF)) {
                i++;
                continue;
            }
            if (!num_vals)
                num_vals = 1;

            printf("[%s] seq=%u pc=0x%lx arg_idx=%u size=%u val=0x%lx\n",
                   type == 0xE ? "ENTRY" : "RET",
                   seq, pc, arg_idx, size, buf[i + 3]);
            i += 3 + num_vals;
        }

        if (ioctl(fd, KCOV_DF_DISABLE, 0))
            perror("ioctl(DISABLE)"), exit(1);

        munmap(buf, BUF_SIZE * sizeof(uint64_t));
        close(fd);
        return 0;
    }

Ring buffer format
------------------

The buffer is an array of ``u64`` words::

        buf[0]: atomic counter -- total words written

Each record occupies 3 + N words:

.. list-table::
   :header-rows: 1

   * - Offset
     - Field
     - Description
   * - 0
     - type_and_seq
     - bits[31:28] = 0xE (entry) or 0xF (return), bits[27:24] = num_vals,
       bits[23:0] = sequence number
   * - 1
     - pc
     - Instrumented function address
   * - 2
     - meta
     - bits[63:56] = arg_idx (0 for return), bits[55:48] = size in bytes,
       bits[47:0] = raw pointer value
   * - 3..N
     - field_val[0..N]
     - Struct field values or single scalar

Magic values:

- ``0xBADADD85``: field read failed (pointer was invalid/freed/poisoned)

Safety
------

- Callbacks are ``notrace``, ``__no_sanitize_coverage``, ``noinline``
  to prevent recursion.
- All pointer reads use ``copy_from_kernel_nofault()`` -- survives
  freed, poisoned, or unmapped memory.
- An ``in_task()`` guard rejects calls from hardirq/softirq/NMI context,
  preventing reentrant buffer corruption.
- No ``printk`` or allocation in the data path.
- When not enabled for a task, overhead is a single boolean check.

Ioctl interface
---------------

.. list-table::
   :header-rows: 1

   * - Command
     - Value
     - Description
   * - KCOV_DF_INIT_TRACK
     - ``_IOR('d', 1, unsigned long)``
     - Allocate buffer (size in u64 words)
   * - KCOV_DF_ENABLE
     - ``_IO('d', 100)``
     - Start collection for current task
   * - KCOV_DF_DISABLE
     - ``_IO('d', 101)``
     - Stop collection
   * - KCOV_DF_REMOTE_ENABLE
     - ``_IO('d', 102)``
     - Publish buffer for kworker/kthread remote capture
   * - KCOV_DF_REMOTE_DISABLE
     - ``_IO('d', 103)``
     - Unpublish buffer from remote capture

Compatibility
-------------

KCOV-Dataflow is completely independent from legacy KCOV:

- Separate device: ``/sys/kernel/debug/kcov_dataflow``
- Separate ioctl namespace (``'d'`` vs ``'c'``)
- Separate per-task buffer
- Both can be used simultaneously without interference
- syzkaller and other KCOV users are unaffected

Rust module support
-------------------

Rust kernel modules are instrumented natively through the build system.
The ``KCOV_DATAFLOW_<module>.o := y`` mechanism works identically for
Rust and C modules. The build system passes
``-Cllvm-args=-sanitizer-coverage-trace-args`` and
``-Cllvm-args=-sanitizer-coverage-trace-ret`` to rustc via
``RUSTFLAGS_KCOV_DATAFLOW``.

Example Makefile for a Rust module::

        obj-m := my_rust_module.o
        KCOV_DATAFLOW_my_rust_module.o := y

Requires a rustc built against LLVM with trace-args/trace-ret support
and ``CONFIG_RUST=y`` in the kernel config.

Selftests
---------

Automated tests and visualization tools are in
``tools/testing/selftests/kcov_dataflow/``::

        # Automated ioctl interface test (TAP output):
        make -C tools/testing/selftests/kcov_dataflow
        vng --user root --exec \
          tools/testing/selftests/kcov_dataflow/user_ioctl/user_ioctl

        # Load a test module and view captured records:
        make LLVM=1 CC=clang M=tools/testing/selftests/kcov_dataflow/eight_struct_args_c modules
        vng --user root --exec \
          "python3 tools/testing/selftests/kcov_dataflow/trigger-view.py \
            eight_struct_args_c --ko \
            tools/testing/selftests/kcov_dataflow/eight_struct_args_c/eight_struct_args_c.ko"

        # Binderfs ioctl capture test (requires CONFIG_ANDROID_BINDER_IPC):
        make -C tools/testing/selftests/kcov_dataflow/binderfs
        vng --user root --exec \
          tools/testing/selftests/kcov_dataflow/binderfs/binderfs_test

See ``tools/testing/selftests/kcov_dataflow/README.rst`` for details.

Tracing child processes
-----------------------

KCOV-Dataflow is per-task: after ``fork()``, the child does not inherit
the enabled state. To trace child processes, re-enable on the inherited
file descriptor in the child before ``exec()``. The ``mmap``'d buffer is
shared (``MAP_SHARED``), so both parent and child write to the same ring
buffer atomically.

.. code-block:: c

    #include <stdio.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <sys/ioctl.h>
    #include <sys/mman.h>
    #include <sys/wait.h>
    #include <unistd.h>
    #include <fcntl.h>

    #define KCOV_DF_INIT_TRACE  _IOR('d', 1, unsigned long)
    #define KCOV_DF_ENABLE      _IO('d', 100)
    #define KCOV_DF_DISABLE     _IO('d', 101)
    #define BUF_SIZE            (1 << 20)

    int main(int argc, char **argv)
    {
        int fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
        ioctl(fd, KCOV_DF_INIT_TRACE, BUF_SIZE);
        uint64_t *buf = mmap(NULL, BUF_SIZE * 8,
                             PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

        /* Enable for parent task. */
        ioctl(fd, KCOV_DF_ENABLE, 0);
        __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

        pid_t pid = fork();
        if (pid == 0) {
            /*
             * Child: re-enable on inherited fd.
             * The shared mmap buffer receives records from both tasks.
             */
            ioctl(fd, KCOV_DF_ENABLE, 0);
            execvp(argv[1], &argv[1]);
            _exit(1);
        }

        waitpid(pid, NULL, 0);
        ioctl(fd, KCOV_DF_DISABLE, 0);

        uint64_t n = __atomic_load_n(&buf[0], __ATOMIC_RELAXED);
        printf("Captured %lu words from parent + child\n", n);

        munmap(buf, BUF_SIZE * 8);
        close(fd);
        return 0;
    }

Note: the child's ``ioctl(fd, KCOV_DF_ENABLE)`` will fail if the parent
has not yet called ``KCOV_DF_DISABLE``, because only one task can be
associated with a descriptor at a time. For true multi-process tracing,
open a separate ``kcov_dataflow`` fd per child, or disable in the parent
before the child enables (as shown above -- the parent is blocked in
``waitpid`` so it generates no records during that time anyway).

Remote tracing (kworker/kthread)
--------------------------------

To capture data from kernel threads (kworkers, kthreads) that are not
direct descendants of user space, use the remote API:

1. User space allocates and publishes a buffer with ``KCOV_DF_REMOTE_ENABLE``
2. The kernel module calls ``kcov_df_remote_start()`` at work entry
3. The kernel module calls ``kcov_df_remote_stop()`` at work exit
4. User space reads the buffer and unpublishes with ``KCOV_DF_REMOTE_DISABLE``

User space setup:

.. code-block:: c

    #include <stdio.h>
    #include <stdint.h>
    #include <sys/ioctl.h>
    #include <sys/mman.h>
    #include <unistd.h>
    #include <fcntl.h>

    #define KCOV_DF_INIT_TRACE      _IOR('d', 1, unsigned long)
    #define KCOV_DF_REMOTE_ENABLE   _IO('d', 102)
    #define KCOV_DF_REMOTE_DISABLE  _IO('d', 103)
    #define BUF_SIZE                (1 << 20)

    int main(void)
    {
        int fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
        ioctl(fd, KCOV_DF_INIT_TRACE, BUF_SIZE);
        uint64_t *buf = mmap(NULL, BUF_SIZE * 8,
                             PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

        /* Publish buffer for remote capture. */
        ioctl(fd, KCOV_DF_REMOTE_ENABLE, 0);

        /* Trigger kworker activity (e.g., write to a file, ioctl). */
        /* ... */
        sleep(1);

        /* Unpublish and read results. */
        ioctl(fd, KCOV_DF_REMOTE_DISABLE, 0);

        uint64_t n = __atomic_load_n(&buf[0], __ATOMIC_RELAXED);
        printf("Captured %lu words from kworker\n", n);

        munmap(buf, BUF_SIZE * 8);
        close(fd);
        return 0;
    }

Kernel module side (called from kworker context):

.. code-block:: c

    #include <linux/kcov.h>

    void my_work_fn(struct work_struct *work)
    {
        kcov_df_remote_start();
        /* ... instrumented code runs here ... */
        kcov_df_remote_stop();
    }

Only one buffer can be published at a time. ``kcov_df_remote_start()``
is a no-op if no buffer is published or if the current task already has
dataflow enabled.

Limitations
-----------

ABI argument mapping
    The LLVM pass maps IR-level arguments to source-level parameters using
    ``DILocalVariable`` debug records (``-g`` required). This correctly
    handles hidden ``sret`` pointers, struct decomposition into multiple
    registers, and C++ ``this`` pointers.

    When debug info is absent or stripped, the pass falls back to positional
    indexing which may misattribute arguments in functions with ABI-inserted
    hidden parameters. The kernel is always built with ``-g``, so this
    limitation does not apply to kernel use.

Struct-by-value reassembly
    When a small struct is passed by value and the ABI decomposes it into
    multiple scalar registers (e.g., ``struct { int x; int y; }`` as two
    ``i32`` values on x86_64), the pass reassembles the fragments into a
    stack slot. The struct field offsets are preserved, but if a field was
    entirely optimized away (no debug record), that slot contains zero.

    In kernel code, structs are always passed by pointer, so this case
    does not arise.

Optimized builds
    At ``-O2`` and above, LLVM may eliminate ``#dbg_value`` records for
    arguments that are dead or fully inlined. Such arguments will emit a
    trace with a null pointer (producing ``0xBADADD85`` in all field
    positions), indicating the argument existed but its value was
    unavailable at runtime.
