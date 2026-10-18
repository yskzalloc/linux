.. SPDX-License-Identifier: GPL-2.0

KCOV-Dataflow: function argument and return value extraction
=============================================================

KCOV-Dataflow captures function arguments and return values, including the
fields of structs passed or returned in memory, at instrumented kernel
function boundaries. It provides per-task, lock-free ring buffers accessible via
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
(``-fsanitize-coverage=trace-args,trace-ret``). What is recorded does not
depend on debug information; with ``CONFIG_DEBUG_INFO`` the compiler also
describes, in DWARF, which source parameter each record holds (see
`Mapping records to the source`_).

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

    #include <linux/kcov_dataflow.h>   /* ioctls, record layout, helpers */
    #define BUF_SIZE            (1 << 20)  /* 1M words = 8MB */

    int main(void)
    {
        int fd;
        uint64_t *buf, n, i;

        fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
        if (fd == -1)
            perror("open"), exit(1);

        /* Allocate buffer (size in u64 words). */
        if (ioctl(fd, KCOV_DF_INIT_TRACK, BUF_SIZE))
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
        while (i + KCOV_DF_RECORD_HDR_WORDS <= 1 + n) {
            uint64_t hdr      = buf[i];
            uint64_t pc       = buf[i + 1];   /* KASLR offset removed */
            uint64_t addr     = buf[i + 2];   /* ENTRY/RET: address of an
                                                 object read in memory,
                                                 else 0 */
            uint32_t type     = KCOV_DF_HDR_TYPE(hdr);
            uint32_t num_vals = KCOV_DF_HDR_NVALS(hdr);
            uint32_t seq      = KCOV_DF_HDR_SEQ(hdr);
            uint32_t arg_idx  = KCOV_DF_HDR_ARGIDX(hdr);
            uint32_t size     = KCOV_DF_HDR_SIZE(hdr);

            if (!num_vals || (type != KCOV_DF_TYPE_ENTRY &&
                              type != KCOV_DF_TYPE_RET &&
                              type != KCOV_DF_TYPE_CMP)) {
                i++;    /* garbage (e.g. reset mid-run): resync */
                continue;
            }
            if (type != KCOV_DF_TYPE_CMP)
                printf("[%s] seq=%u pc=0x%lx addr=0x%lx arg_idx=%u size=%u val=0x%lx\n",
                       type == KCOV_DF_TYPE_ENTRY ? "ENTRY" : "RET",
                       seq, pc, addr, arg_idx, size, buf[i + 3]);
            i += KCOV_DF_RECORD_WORDS(num_vals);
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
     - header
     - bits[63:56] = arg_idx (0 for return), bits[55:48] = size in bytes
       (clamped to 255), bits[47:32] = num_vals (>= 1),
       bits[31:28] = type: ``KCOV_DF_TYPE_ENTRY`` (0xE),
       ``KCOV_DF_TYPE_RET`` (0xF) or ``KCOV_DF_TYPE_CMP`` (0xC),
       bit 24 = ``KCOV_DF_HDR_MEM``: the values were read in memory at
       word 2, bits[23:0] = sequence number
   * - 1
     - pc
     - Address of the call that produced the record, with the KASLR offset
       removed (same as the PCs mainline kcov records), so it can be
       symbolized against vmlinux; add the runtime offset back for
       ``/proc/kallsyms``. It is the call's return address minus one, inside
       the call instruction; every record has a call of its own, so the pc
       identifies the record exactly
   * - 2
     - addr / cmp_type
     - ENTRY/RET: the address the field values were read from, and 0 when
       the record carries the value itself (may be NULL/ERR_PTR as the
       callee received it, in which case the values are ``0xBADADD85``).
       CMP: the comparison type, ``KCOV_CMP_SIZE()``/``KCOV_CMP_CONST``
       bits from linux/kcov.h
   * - 3..3+num_vals
     - values
     - A single value; with ``KCOV_DF_HDR_MEM``, up to 8 bytes each read at
       word 2, in memory order from the word's lowest-addressed byte and
       zero-filled -- the fields of an object in memory, or 8-byte pieces of
       what a pointer points to; or the two CMP operands

``area[0]`` never exceeds the buffer size minus one and every counted word
has been written, so a consumer that walks ``area[0]`` words never leaves
its mapping. All of the above is defined in ``include/uapi/linux/kcov_dataflow.h``
(``KCOV_DF_HDR_*()``, ``KCOV_DF_RECORD_WORDS()``).

What is recorded is decided by the function's LLVM IR alone, and is the same
with or without debug information:

- ``arg_idx`` is the position of the argument in the IR, the ABI's view of
  the signature, not the source parameter number. A struct the ABI splits
  across registers is several IR arguments (``struct { double d; long l; }``
  is two on x86_64), or one aggregate reported as several records with the
  same ``arg_idx`` (``[2 x i64]`` on arm64). A hidden struct-return pointer
  is not recorded, but keeps its position, so the next argument is index 1.
- A value -- an integer, a pointer, a floating-point value -- is recorded as
  it comes, with word 2 zero. A pointer is recorded as the address it holds.
- An object the IR marks as passed in memory (a ``byval`` argument, as
  x86_64 passes a large struct) or returned through a caller-provided buffer
  (``sret``) arrives as an address, which word 2 keeps; the fields of its IR
  type are read out of it. A field wider than 8 bytes is read in 8-byte
  pieces, and so is an object whose IR type is an opaque byte array, as
  rustc types every struct it passes or returns in memory (``[32 x i8]``):
  all of it is recorded, not its first 8 bytes. A large struct arm64 passes
  by reference is a pointer argument, recorded as one -- and, as clang
  marks it ``dereferenceable(sizeof(struct))``, with a snapshot of the
  struct behind it (below).
- A pointer argument or return value the IR says is ``dereferenceable(N)``
  or ``dereferenceable_or_null(N)`` additionally comes with a raw snapshot of
  what it points to: word 2 is the pointer, the size in the header is the
  number of bytes read, min(N, ``CONFIG_KCOV_DATAFLOW_POINTEE_BYTES``), and
  the values are those bytes 8 at a time. The record looks like one of an
  object in memory; the ``__sancov_dataflow`` descriptor of its pc says it is
  a pointer, and the DWARF says what the bytes are (see "Mapping records to
  the source"). Which pointers get one is up to the compiler's IR: rustc
  marks ``&T`` and ``&mut T`` arguments ``dereferenceable(size_of::<T>())``
  and ``Option<&T>`` ``dereferenceable_or_null``, but not raw pointers,
  slices, ``&`` of a ``!Freeze`` type (``Opaque<T>``, ``Cell``) or ``&mut``
  of a ``!Unpin`` one, nor returns; clang marks C++ references, a struct
  the ABI passes by reference (arm64, over 16 bytes) and a C array
  parameter of static size (``const struct foo p[static 1]``), but no plain C
  pointer.
- An argument the function does not use is still recorded. If it is an
  object in memory, it is not read -- callers may pass anything for it --
  and is recorded with size 0.

Pointee snapshots and access records
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are two ways the bytes behind a pointer argument are recorded, and
they mean different things:

- A **pointee snapshot** (ENTRY or RET record, ``KCOV_DF_HDR_MEM``) is read
  by the collector at the trace point -- function entry, or the return --
  because the compiler's IR has an explicit contract that the bytes may be
  read there (``dereferenceable(N)``). It is the first N bytes of the
  pointee as they were at that moment.
- An **access record** (``KCOV_DF_TYPE_ACCESS``, with
  ``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS``) is the value of one load or store
  the function itself made through a pointer argument, at a constant offset
  from it (``p->field``, ``p->a.b[2]``, ``container_of(p, ...)->field``),
  recorded right after the access when the access executed. Word 3 is the
  value the load returned or the store wrote, the header size its bytes, the
  header argidx the pointer argument, and word 2 the kind:
  ``KCOV_DF_ACCESS_STORE`` (else a load), ``KCOV_DF_ACCESS_VOLATILE``,
  ``KCOV_DF_ACCESS_ATOMIC``. The value is the program's own: the collector
  reads nothing, and the compiler adds no load, so KASAN and KCSAN see the
  same accesses with and without the option. Which bytes of the pointee the
  access covered is in the record's ``__sancov_dataflow`` descriptor (a
  signed offset; a value wider than 8 bytes is several records, one per
  8-byte piece).

An access record is not a snapshot of the pointee. It covers only the bytes
the function accessed, and says nothing of the members it did not touch; it
is the value at the time of the access, which may be after locks were taken
or other calls changed the pointee, not the value at the call; one member
may have many records, one per executed access, in execution order; and a
store record does not say the value was still in memory afterwards. Records
are emitted in the middle of a function, after any records of the functions
it called before the access: a consumer attributes them to the innermost
active frame of the function whose call site they carry (see
``trigger-view.py``).

Not recorded: accesses through a pointer loaded from memory, at a variable
offset, or rebuilt from an integer; ``memcpy()``/``memset()``; read-modify-
write and compare-exchange operations; inline assembly, which is how the
kernel implements its atomics, ``get_user()``/``put_user()`` and MMIO
accessors. Volatile accesses (``READ_ONCE()``/``WRITE_ONCE()``) need
``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS_VOLATILE``, and the compiler's own atomic
loads and stores ``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS_ATOMIC``. Nothing is ever
read to stand in for an access that is not recorded.

Compatibility: ACCESS records exist only when the kernel is built with
``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS``; a decoder walking records by
``KCOV_DF_RECORD_WORDS(nvals)`` skips a record type it does not know, so an
older decoder loses the access records but misreads nothing. Without the
option the record stream is unchanged.

Magic values:

- ``0xBADADD85``: a field read failed (the address was invalid, freed or
  poisoned, or NULL, as a ``dereferenceable_or_null`` pointer may be), or the
  header size is 0, meaning the compiler had no value to report: an unused
  object, or a value with no fixed-size bit pattern

Safety
------

- Callbacks are ``notrace``, ``__no_sanitize_coverage``, ``noinline``
  to prevent recursion.
- Only reading an object passed or returned in memory, or the bytes behind
  a pointer the IR says are dereferenceable, touches memory -- never an
  ACCESS record, whose value arrives in a register -- and it does so
  with
  ``copy_from_kernel_nofault()`` -- surviving freed, poisoned or unmapped
  memory. A value that arrives in a register cannot fault at all.
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
     - ``_IOW('d', 102, __u64)`` -- argument is a pointer to the handle
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

    #include <linux/kcov_dataflow.h>   /* ioctls, record layout, helpers */
    #define BUF_SIZE            (1 << 20)

    int main(int argc, char **argv)
    {
        int fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
        ioctl(fd, KCOV_DF_INIT_TRACK, BUF_SIZE);
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

    #include <linux/kcov.h>            /* kcov_remote_handle() */
    #include <linux/kcov_dataflow.h>
    #define BUF_SIZE                (1 << 20)

    int main(void)
    {
        int fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
        ioctl(fd, KCOV_DF_INIT_TRACK, BUF_SIZE);
        uint64_t *buf = mmap(NULL, BUF_SIZE * 8,
                             PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

        /*
         * Publish the buffer under a remote handle. The handle must be a
         * valid kcov_remote_handle() encoding (KCOV_SUBSYSTEM_COMMON with a
         * nonzero instance, or KCOV_SUBSYSTEM_USB) and is the value the
         * kernel side passes to kcov_df_remote_start(); one handle per fd,
         * and not while KCOV_DF_ENABLE is active on the same fd.
         */
        __u64 handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, 1);
        if (ioctl(fd, KCOV_DF_REMOTE_ENABLE, &handle))
            perror("ioctl(REMOTE_ENABLE)"), exit(1);

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

Pointer arguments
    A pointer is recorded as the address it holds, and what it points to is
    read only as far as the IR says it is dereferenceable. Which bytes behind
    any other pointer are valid to read at function entry is not something
    the IR says, and reading as far as debug information describes would let
    ``-g`` change what is recorded. In practice that means the pointees of
    Rust references are recorded and those of C pointers are not: of the
    pointer arguments of a sample of 557 C objects of an x86_64 build, none
    has a ``dereferenceable`` attribute; of those of ``rust/kernel.o`` and
    the Rust binder driver, 42%. For the rest, the pointee's type and field
    layout are available offline from DWARF (``sancov -symbolize-dataflow``
    reports them as ``pointee``, with ``bytes_read`` 0), its values are not
    -- except, with ``CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS``, the values the
    function itself loads and stores through it, as access records. Measured
    statically on the same objects, at least one pointee byte of 51% of the C
    pointer arguments of an x86_64 build is then recorded (54% with the
    volatile and atomic options), 55% (58%) on arm64, and, with snapshots,
    55% of the Rust ones: shares of pointer arguments with any recorded
    pointee byte, not of arguments or structs reconstructed.

Struct-by-value in registers
    A small struct passed or returned by value has no address once the ABI
    has put it in registers (e.g. ``struct { int x; int y; }`` as one ``i64``
    on x86_64). There is nothing to read fields out of, so each IR value is
    recorded as it is. The DWARF source map says which bits of which source
    parameter each record holds.

Inlined callees
    A function the compiler inlined is no function of its own any more, and
    its arguments are not recorded: arguments are those of the functions
    that remain after inlining. ``CONFIG_KCOV_DATAFLOW_NO_INLINE`` makes
    more of them visible in the objects that opt in explicitly with
    ``KCOV_DATAFLOW_<object>.o := y`` or ``KCOV_DATAFLOW := y`` -- never in
    the whole tree under ``CONFIG_KCOV_DATAFLOW_INSTRUMENT_ALL``, because the
    kernel cannot be built with ``-fno-inline``: some inline asm ``"i"``
    operands depend on the inliner folding a value to a constant.

Mapping records to the source
-----------------------------

Every trace-args/trace-ret call also gets a descriptor in the
``__sancov_dataflow`` section, kept in vmlinux and in modules: the call's
address and what it reports -- the IR argument or return, which element of
an aggregate, the value class (integer, pointer, float, vector, object) and
size, and whether a pointer came with a snapshot of its pointee. With ``CONFIG_DEBUG_INFO`` the compiler adds a
``DW_TAG_LLVM_sancov_observation`` DIE per observation to the function's
DWARF, naming the source parameter, and the bits of it, that the
observation holds. Neither changes what is recorded.

``sancov -symbolize-dataflow`` joins the two, for vmlinux or a module::

        sancov -symbolize-dataflow drivers/foo/foo.ko

and reports, for every call site, its function and line, the observation,
and the source parameter: its name and type, the struct fields of an object
read in memory, and the pointee type and fields of a pointer -- with
``bytes_read``, the size of the snapshot, and which of the fields it holds
wholly, in part (``"complete": false``) or not at all (``"observed":
false``), so that a consumer can cut the value words of a snapshot record
into members by their ``bit_offset``. An access record's call site is
``"kind": "access"``, and lists the members of the pointee its bytes overlap,
with a source expression (``o->in.x``) and where in the value each is. A record is
looked up by its ``pc`` (for a module, relative to the module's ``.text``):
the address ``sancov`` reports for a call is the one the kernel records.
