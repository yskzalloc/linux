// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/sample/local.c — libFuzzer harness for samples/harden/local.c.
//
// This is the "bring-your-own-coverage" (BYOC) pattern from the study: the
// code under test is in the KERNEL, so libFuzzer cannot see its coverage
// directly. Instead we:
//   1. mmap the driver's zero-copy shared page and write the fuzz input there,
//   2. collect the kernel's per-thread KCOV signal for the parsing ioctl,
//   3. fold it into libFuzzer's __libfuzzer_extra_counters array so the engine
//      treats kernel coverage exactly like in-process coverage.
//
// Because the parser runs in the ioctl's own syscall context, plain
// KCOV_ENABLE on this thread is enough — this is the LOCAL coverage case.
//
// Two optional behaviours are controlled by environment variables:
//   HARDEN_REPRO=<path>  write each trial input to <path> before running it, so
//                        after a KASAN panic tears down the VM the file holds
//                        the crashing input (libFuzzer cannot write its own
//                        crash-<sha1> once the guest dies). Needs a writable
//                        host mount (harden.sh boots with `vng --rw`).
//   HARDEN_CMP=1         use KCOV comparison mode (KCOV_TRACE_CMP): replay the
//                        kernel's compare operands into libFuzzer's TORC so the
//                        mutator can splice them (study Part IV §27b). Coverage
//                        then comes from compare-site PCs.
//
// Build with the project clang and run INSIDE vng (see harden.sh):
//   clang -g -O1 -fsanitize=fuzzer,address tools/harden/sample/local.c -o /tmp/f
//   /tmp/f -runs=1000000

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

// --- driver ABI (must match samples/harden/local.c) ---
#define HARDEN_RUN	_IO('H', 1)
#define PAGE_BYTES	4096

// --- KCOV ABI (from include/uapi/linux/kcov.h) ---
#define KCOV_INIT_TRACE	_IOR('c', 1, unsigned long)
#define KCOV_ENABLE	_IO('c', 100)
#define KCOV_TRACE_PC	0
#define KCOV_TRACE_CMP	1
#define KCOV_CMP_CONST	(1 << 0)
#define KCOV_CMP_SIZE(n) ((n) << 1)
#define KCOV_CMP_MASK	KCOV_CMP_SIZE(3)
#define COVER_WORDS	(64 << 10)   // KCOV buffer size in unsigned longs
#define KCOV_WORDS_PER_CMP 4         // TRACE_CMP record: {type, arg1, arg2, pc}

// libFuzzer's compare callbacks (exported by the fuzzer runtime). Replaying the
// kernel's compares into these feeds the Table Of Recent Compares (study §20).
void __sanitizer_cov_trace_cmp1(uint8_t, uint8_t);
void __sanitizer_cov_trace_cmp2(uint16_t, uint16_t);
void __sanitizer_cov_trace_cmp4(uint32_t, uint32_t);
void __sanitizer_cov_trace_cmp8(uint64_t, uint64_t);

// libFuzzer extra counters: every non-zero byte here is a coverage feature,
// identical in status to compiler-inserted counters (study Part II §12).
__attribute__((section("__libfuzzer_extra_counters")))
static uint8_t kcov_counters[64 << 10];

static int dev_fd = -1;
static volatile uint8_t *shared;      // co-mapped driver page (zero copy)
static unsigned long *cover;          // KCOV per-thread buffer
static int cmp_mode;                  // HARDEN_CMP: use KCOV_TRACE_CMP
static int repro_fd = -1;             // HARDEN_REPRO: last-input log

static inline uint32_t mix(uint64_t pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdULL;
	pc ^= pc >> 33;
	return (uint32_t)pc;
}

static inline void bump(uint64_t pc)
{
	kcov_counters[mix(pc) % (uint32_t)sizeof(kcov_counters)]++;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;

	cmp_mode = getenv("HARDEN_CMP") != NULL;
	const char *rp = getenv("HARDEN_REPRO");
	if (rp) {
		repro_fd = open(rp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (repro_fd < 0) perror("open HARDEN_REPRO");  // non-fatal
	}

	// 1. Open the buggy driver and co-map its shared page.
	dev_fd = open("/dev/harden_local", O_RDWR);
	if (dev_fd < 0) { perror("open /dev/harden_local"); exit(1); }
	shared = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, dev_fd, 0);
	if (shared == MAP_FAILED) { perror("mmap device"); exit(1); }

	// 2. Set up KCOV on THIS thread (local coverage), in PC or CMP mode.
	int kfd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kfd < 0) { perror("open kcov (mount debugfs?)"); exit(1); }
	if (ioctl(kfd, KCOV_INIT_TRACE, COVER_WORDS)) { perror("KCOV_INIT"); exit(1); }
	cover = mmap(NULL, COVER_WORDS * sizeof(unsigned long),
		     PROT_READ | PROT_WRITE, MAP_SHARED, kfd, 0);
	if (cover == MAP_FAILED) { perror("mmap kcov"); exit(1); }
	if (ioctl(kfd, KCOV_ENABLE, cmp_mode ? KCOV_TRACE_CMP : KCOV_TRACE_PC)) {
		perror("KCOV_ENABLE"); exit(1);
	}
	fprintf(stderr, "[harness] mode=%s repro=%s\n",
		cmp_mode ? "TRACE_CMP" : "TRACE_PC", repro_fd >= 0 ? "on" : "off");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t n = size < PAGE_BYTES ? size : PAGE_BYTES;

	// Reproducer capture: persist THIS input before we run it, so if the
	// ioctl below panics the kernel, the crashing bytes survive on the host.
	if (repro_fd >= 0) {
		lseek(repro_fd, 0, SEEK_SET);
		if (ftruncate(repro_fd, 0) == 0 && write(repro_fd, data, n) >= 0)
			fsync(repro_fd);   // 9p is cached; fsync makes the input durable
				           // on the host before a KASAN panic (has cost).
	}

	// Step 1: publish the fuzz input into the co-mapped page (zero copy).
	memcpy((void *)shared, data, n);
	if (n < PAGE_BYTES)
		memset((void *)shared + n, 0, PAGE_BYTES - n);

	// Step 2: reset the KCOV counter, then run the kernel parser in this
	// ioctl's syscall context (its signal lands in `cover`).
	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
	ioctl(dev_fd, HARDEN_RUN);   // <-- a kernel OOB write panics the VM here

	// Step 3: turn the KCOV signal into libFuzzer features.
	unsigned long nrec = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	if (!cmp_mode) {
		// PC mode: each word is a covered basic-block PC.
		for (unsigned long i = 1; i <= nrec && i <= COVER_WORDS - 1; i++)
			bump(cover[i]);
	} else {
		// CMP mode: each record is {type, arg1, arg2, pc}. Replay the
		// operands into libFuzzer's TORC and use the pc as coverage.
		for (unsigned long i = 0;
		     i < nrec && (i + 1) * KCOV_WORDS_PER_CMP < COVER_WORDS; i++) {
			unsigned long *r = &cover[1 + i * KCOV_WORDS_PER_CMP];
			uint64_t type = r[0], a1 = r[1], a2 = r[2], pc = r[3];
			switch (1u << ((type & KCOV_CMP_MASK) >> 1)) {  // operand size
			case 1: __sanitizer_cov_trace_cmp1((uint8_t)a1, (uint8_t)a2); break;
			case 2: __sanitizer_cov_trace_cmp2((uint16_t)a1, (uint16_t)a2); break;
			case 4: __sanitizer_cov_trace_cmp4((uint32_t)a1, (uint32_t)a2); break;
			default: __sanitizer_cov_trace_cmp8(a1, a2); break;
			}
			bump(pc);
		}
	}
	return 0;
}
