/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KCOV_DATAFLOW_H
#define _LINUX_KCOV_DATAFLOW_H

#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * User space ABI of /sys/kernel/debug/kcov_dataflow, see
 * Documentation/dev-tools/kcov-dataflow.rst.
 *
 * KCOV_DF_INIT_TRACK takes the buffer size in u64 words by value (same
 * convention as KCOV_INIT_TRACE). KCOV_DF_REMOTE_ENABLE takes a pointer to a
 * __u64 remote handle encoded with kcov_remote_handle() (linux/kcov.h), so the
 * full 64-bit value survives 32-bit and compat callers.
 */
#define KCOV_DF_INIT_TRACK	_IOR('d', 1, unsigned long)
#define KCOV_DF_ENABLE		_IO('d', 100)
#define KCOV_DF_DISABLE		_IO('d', 101)
#define KCOV_DF_REMOTE_ENABLE	_IOW('d', 102, __u64)
#define KCOV_DF_REMOTE_DISABLE	_IO('d', 103)

/*
 * Buffer layout (all u64 words):
 *
 *   area[0]                number of record words written after area[0]
 *   area[1 + n ..]         records, back to back, each:
 *
 *     [0] header           see KCOV_DF_HDR_* below
 *     [1] pc               the call that produced the record, its return
 *                          address minus one; KASLR offset removed, like the
 *                          PCs mainline kcov records. Every record has a call
 *                          of its own, so the pc identifies it: which
 *                          function, and - through the __sancov_dataflow
 *                          descriptor and the DWARF the compiler emits for
 *                          that call, e.g. with "sancov -symbolize-dataflow" -
 *                          which IR argument, element and source parameter
 *     [2] ENTRY/RET: the address the value words were read from, with
 *                    KCOV_DF_HDR_MEM set, and 0 when the record carries the
 *                    value itself (nvals == 1); an address the callee
 *                    received as NULL/ERR_PTR leaves the value words holding
 *                    KCOV_DF_MAGIC_BAD
 *         CMP:       comparison type, KCOV_CMP_SIZE()/KCOV_CMP_CONST bits
 *                    (linux/kcov.h)
 *         ACCESS:    the access kind, KCOV_DF_ACCESS_* below
 *     [3 .. 3 + nvals)     value words: the value itself (nvals == 1), the
 *                          words read at word [2] (KCOV_DF_HDR_MEM), or the
 *                          two CMP operands (nvals == 2)
 *
 * What is recorded is the function's arguments as the compiler lowered them
 * (its IR arguments), not its source parameters: the argument index is the IR
 * position. A struct the ABI splits across registers is several arguments, or
 * several records with one index; a hidden struct-return pointer is not
 * recorded but keeps its position.
 *
 * A value - an integer, a pointer, a floating-point value - is recorded as it
 * comes, with word [2] zero; a pointer as the address it holds. Memory is read
 * only where the compiler's IR says it may be, and then KCOV_DF_HDR_MEM is set,
 * word [2] holds the address, and each value word holds up to 8 bytes read
 * from it, in memory order from the word's lowest-addressed byte (the low
 * bytes on a little-endian kernel), zero-filled:
 *
 *  - an object the ABI passes in memory (a byval argument) or returns through
 *    a caller-provided buffer (sret): the fields of its IR type, a field wider
 *    than 8 bytes, or an opaque byte array as rustc types such objects, in
 *    8-byte pieces; size is the object's;
 *  - a pointer argument or return value the IR says is dereferenceable(N)
 *    (a Rust &T, a C++ reference, a C "T p[static 1]"; a plain C pointer is
 *    not): word [2] is the pointer, and the value words are a raw snapshot of
 *    the first min(N, CONFIG_KCOV_DATAFLOW_POINTEE_BYTES) bytes it points to,
 *    8 at a time; size is the number of bytes. For dereferenceable_or_null
 *    the pointer may be NULL.
 *
 * An ACCESS record (CONFIG_KCOV_DATAFLOW_POINTEE_ACCESS) is the value of a
 * load or store an instrumented function made through one of its pointer
 * arguments, recorded after the access, in the middle of the function: word
 * [3] is the value the load returned or the store wrote, size its bytes,
 * argidx the pointer argument, word [2] whether it was a load or a store. The
 * value comes from the compiler; nothing is read for it, KCOV_DF_HDR_MEM is
 * never set. Where in the pointee the access was is for the record's
 * __sancov_dataflow descriptor to say; a wider access is several records. An
 * ACCESS record says what the function did with the pointee when it did it,
 * not what the pointee held at the call, nor that a stored value stayed.
 * A decoder that predates ACCESS records skips them by nvals.
 *
 * Which of the two a record is, and what the bytes are in source terms, is
 * for the __sancov_dataflow descriptor of its pc and the DWARF of the binary to
 * say ("sancov -symbolize-dataflow" cuts a snapshot into the pointee's
 * members). An object the function never uses, and a value with no fixed-size
 * bit pattern, are recorded with size 0 and KCOV_DF_MAGIC_BAD in their value
 * words.
 *
 * The header packs:
 *
 *   bits  0..23  per-task record sequence number
 *   bit  24      KCOV_DF_HDR_MEM: the value words were read at word [2]
 *   bits 28..31  record type, KCOV_DF_TYPE_*
 *   bits 32..47  nvals, the number of value words that follow word [2]
 *   bits 48..55  ENTRY/RET/ACCESS: size in bytes of the traced argument/return
 *                value, or of the accessed value (clamped to 255)
 *   bits 56..63  ENTRY/ACCESS: argument index (clamped to 255); RET: 0
 *
 * A consumer walks the buffer as
 *
 *	pos = 1;
 *	while (pos < 1 + area[0]) {
 *		hdr = area[pos];
 *		nvals = KCOV_DF_HDR_NVALS(hdr);
 *		...
 *		pos += KCOV_DF_RECORD_WORDS(nvals);
 *	}
 *
 * area[0] never exceeds the buffer size minus one, and every counted word has
 * been written, so the walk above stays inside the mapping.
 */
#define KCOV_DF_TYPE_ACCESS	0xA
#define KCOV_DF_TYPE_CMP	0xC
#define KCOV_DF_TYPE_ENTRY	0xE
#define KCOV_DF_TYPE_RET	0xF

#define KCOV_DF_HDR_SEQ_MASK	0x00FFFFFFULL
#define KCOV_DF_HDR_MEM		(1ULL << 24)
#define KCOV_DF_HDR_TYPE_SHIFT	28
#define KCOV_DF_HDR_TYPE_MASK	0xFULL
#define KCOV_DF_HDR_NVALS_SHIFT	32
#define KCOV_DF_HDR_NVALS_MASK	0xFFFFULL
#define KCOV_DF_HDR_SIZE_SHIFT	48
#define KCOV_DF_HDR_SIZE_MASK	0xFFULL
#define KCOV_DF_HDR_ARGIDX_SHIFT 56
#define KCOV_DF_HDR_ARGIDX_MASK	0xFFULL

#define KCOV_DF_HDR_SEQ(h)	((h) & KCOV_DF_HDR_SEQ_MASK)
#define KCOV_DF_HDR_TYPE(h)	(((h) >> KCOV_DF_HDR_TYPE_SHIFT) & KCOV_DF_HDR_TYPE_MASK)
#define KCOV_DF_HDR_NVALS(h)	(((h) >> KCOV_DF_HDR_NVALS_SHIFT) & KCOV_DF_HDR_NVALS_MASK)
#define KCOV_DF_HDR_SIZE(h)	(((h) >> KCOV_DF_HDR_SIZE_SHIFT) & KCOV_DF_HDR_SIZE_MASK)
#define KCOV_DF_HDR_ARGIDX(h)	(((h) >> KCOV_DF_HDR_ARGIDX_SHIFT) & KCOV_DF_HDR_ARGIDX_MASK)

/*
 * Word [2] of an ACCESS record: a store if KCOV_DF_ACCESS_STORE, else a load;
 * volatile, atomic, and for an atomic access its LLVM ordering (2 relaxed,
 * 4 acquire, 5 release, 6 acq_rel, 7 seq_cst) in bits 4..6.
 */
#define KCOV_DF_ACCESS_STORE		0x1ULL
#define KCOV_DF_ACCESS_VOLATILE		0x2ULL
#define KCOV_DF_ACCESS_ATOMIC		0x4ULL
#define KCOV_DF_ACCESS_ORDERING(w)	(((w) >> 4) & 0x7)

/* Words per record: header, pc, address/cmp-type, then the value words. */
#define KCOV_DF_RECORD_HDR_WORDS	3
#define KCOV_DF_RECORD_WORDS(nvals)	(KCOV_DF_RECORD_HDR_WORDS + (nvals))

/* Largest nvals a record can carry; longer field lists are truncated. */
#define KCOV_DF_MAX_VALS	KCOV_DF_HDR_NVALS_MASK

/*
 * Value word written when there was nothing to record: a field the traced
 * address could not be read from, or a value the compiler could not report
 * (header size 0).
 */
#define KCOV_DF_MAGIC_BAD	0xBADADD85ULL

#endif /* _LINUX_KCOV_DATAFLOW_H */
