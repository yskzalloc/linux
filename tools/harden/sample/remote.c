// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/sample/remote.c — libFuzzer harness for samples/harden/remote.c.
//
// Identical in spirit to tools/harden/sample/local.c, with ONE difference that
// is the whole point: the kernel parser runs on a workqueue kthread, not in
// our ioctl's syscall context. Plain KCOV_ENABLE would therefore capture
// nothing. We use KCOV_REMOTE_ENABLE with a non-zero `common_handle`; the
// driver reads that handle (via kcov_common_handle()) and the worker brackets
// its parse with kcov_remote_start_common()/kcov_remote_stop(), so the kworker
// coverage is routed back into THIS fd's buffer.
//
// Build and run INSIDE vng (see vng.sh):
//   clang -g -O1 -fsanitize=fuzzer,address tools/harden/sample/remote.c \
//         -o /tmp/harden_remote_fuzz
//   modprobe harden_remote
//   mount -t debugfs none /sys/kernel/debug 2>/dev/null
//   /tmp/harden_remote_fuzz -runs=1000000
//
// Expected: same OOB-write KASAN panic as the local case, but proving remote
// (kworker) coverage works. See Part VII of libfuzzer-study.html.

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

// --- driver ABI (must match samples/harden/remote.c) ---
#define HARDEN_RUN	_IO('H', 1)
#define PAGE_BYTES	4096

// --- KCOV ABI (from include/uapi/linux/kcov.h) ---
#define KCOV_INIT_TRACE		_IOR('c', 1, unsigned long)
#define KCOV_REMOTE_ENABLE	_IOW('c', 102, struct kcov_remote_arg)
#define KCOV_TRACE_PC		0
#define COVER_WORDS		(64 << 10)

#define KCOV_SUBSYSTEM_COMMON	(0x00ull << 56)
#define KCOV_INSTANCE_MASK	(0xffffffffull)
// Any non-zero instance id works for a single collecting process; use a fixed
// one that both sides agree on. (The kernel only requires a common handle to
// be non-zero — see kcov_check_handle().)
#define KCOV_COMMON_ID		0x42

struct kcov_remote_arg {
	uint32_t	trace_mode;
	uint32_t	area_size;
	uint32_t	num_handles;
	uint64_t	common_handle;
	uint64_t	handles[0];
};

static inline uint64_t kcov_remote_handle(uint64_t subsys, uint64_t inst)
{
	return subsys | (inst & KCOV_INSTANCE_MASK);
}

__attribute__((section("__libfuzzer_extra_counters")))
static uint8_t kcov_counters[64 << 10];

static int dev_fd = -1;
static volatile uint8_t *shared;
static unsigned long *cover;
static int repro_fd = -1;             // HARDEN_REPRO: durable last-input log

static inline uint32_t mix(uint64_t pc)
{
	pc ^= pc >> 33;
	pc *= 0xff51afd7ed558ccdULL;
	pc ^= pc >> 33;
	return (uint32_t)pc;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;

	const char *rp = getenv("HARDEN_REPRO");
	if (rp) {
		repro_fd = open(rp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (repro_fd < 0) perror("open HARDEN_REPRO");  // non-fatal
	}

	dev_fd = open("/dev/harden_remote", O_RDWR);
	if (dev_fd < 0) { perror("open /dev/harden_remote"); exit(1); }
	shared = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED,
		      dev_fd, 0);
	if (shared == MAP_FAILED) { perror("mmap device"); exit(1); }

	int kfd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kfd < 0) { perror("open kcov (mount debugfs?)"); exit(1); }
	if (ioctl(kfd, KCOV_INIT_TRACE, COVER_WORDS)) { perror("KCOV_INIT"); exit(1); }
	cover = mmap(NULL, COVER_WORDS * sizeof(unsigned long),
		     PROT_READ | PROT_WRITE, MAP_SHARED, kfd, 0);
	if (cover == MAP_FAILED) { perror("mmap kcov"); exit(1); }

	// REMOTE enable: install a common handle. The driver's worker uses the
	// matching kcov_remote_start_common() so its coverage lands here.
	struct kcov_remote_arg *arg = calloc(1, sizeof(*arg));
	if (!arg) { perror("calloc"); exit(1); }
	arg->trace_mode = KCOV_TRACE_PC;
	arg->area_size = COVER_WORDS;
	arg->num_handles = 0;   // no global handles; only the common handle
	arg->common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON,
						KCOV_COMMON_ID);
	if (ioctl(kfd, KCOV_REMOTE_ENABLE, arg)) { perror("KCOV_REMOTE_ENABLE"); exit(1); }
	free(arg);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t n = size < PAGE_BYTES ? size : PAGE_BYTES;

	// Reproducer capture: persist THIS input (durable via fsync) before the
	// worker runs it, so a KASAN panic leaves the crashing bytes on the host.
	if (repro_fd >= 0) {
		lseek(repro_fd, 0, SEEK_SET);
		if (ftruncate(repro_fd, 0) == 0 && write(repro_fd, data, n) >= 0)
			fsync(repro_fd);
	}

	memcpy((void *)shared, data, n);
	if (n < PAGE_BYTES)
		memset((void *)shared + n, 0, PAGE_BYTES - n);

	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
	// The ioctl blocks until the worker (which produced remote coverage)
	// has finished, so `cover` is complete when we read it.
	ioctl(dev_fd, HARDEN_RUN);

	unsigned long ncov = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	for (unsigned long i = 1; i <= ncov && i <= COVER_WORDS - 1; i++) {
		uint32_t idx = mix(cover[i]) % (uint32_t)sizeof(kcov_counters);
		kcov_counters[idx]++;
	}
	return 0;
}
