// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/fuzztest/kcov_feedback.cc — see kcov_feedback.h.

#include "kcov_feedback.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace harden {
namespace {

// --- KCOV ABI (include/uapi/linux/kcov.h) ---
#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, struct kcov_remote_arg)
constexpr unsigned long kTracePc = 0;
constexpr unsigned long kCoverWords = 64 << 10;
constexpr uint64_t kSubsystemCommon = 0x00ull << 56;
constexpr uint64_t kCommonId = 0x42;  // must match nothing else; any non-zero

struct kcov_remote_arg {
  uint32_t trace_mode;
  uint32_t area_size;
  uint32_t num_handles;
  uint64_t common_handle;
  uint64_t handles[0];
};

[[noreturn]] void Die(const char* what) {
  perror(what);
  exit(1);
}

// Same murmur-style finaliser as tools/harden/sample/local.c.
inline uint64_t Mix(uint64_t x) {
  x ^= x >> 33;
  x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33;
  return x;
}

// ---------------------------------------------------------------------------
// The seam. Centipede finds this array through the linker-generated
// __start_/__stop___centipede_extra_features symbols (centipede/sancov_state.cc)
// and reads it after every input. `used, retain` stop the compiler and linker
// from discarding an array nobody in the program reads.
constexpr size_t kMaxKernelFeatures = 1 << 16;
__attribute__((used, retain, section("__centipede_extra_features")))
uint64_t g_kernel_features[kMaxKernelFeatures];

constexpr uint64_t kPcDomain = 0;    // -> feature_domains::kUserDomains[0]
constexpr uint64_t kEdgeDomain = 1;  // -> feature_domains::kUserDomains[1]

inline uint64_t MakeFeature(uint64_t domain, uint64_t hash) {
  // Centipede reduces the id mod kDomainSize (1<<27) itself; we only have to
  // keep the id inside 32 bits and make sure the whole value is never 0
  // (0 means "unset" and is skipped).
  uint32_t id = static_cast<uint32_t>(hash) | 1;
  return (domain << 32) | id;
}

struct ThreadKcov {
  pid_t tid = 0;
  KcovMode mode;
  std::unique_ptr<Kcov> kcov;
};
thread_local ThreadKcov t_kcov;

}  // namespace

Kcov::Kcov(KcovMode mode) {
  fd_ = open("/sys/kernel/debug/kcov", O_RDWR);
  if (fd_ < 0) Die("open /sys/kernel/debug/kcov (mount debugfs?)");
  if (ioctl(fd_, KCOV_INIT_TRACE, kCoverWords)) Die("KCOV_INIT_TRACE");
  void* p = mmap(nullptr, kCoverWords * sizeof(unsigned long),
                 PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
  if (p == MAP_FAILED) Die("mmap kcov");
  cover_ = static_cast<unsigned long*>(p);

  if (mode == KcovMode::kLocal) {
    if (ioctl(fd_, KCOV_ENABLE, kTracePc)) Die("KCOV_ENABLE");
  } else {
    kcov_remote_arg arg = {};
    arg.trace_mode = kTracePc;
    arg.area_size = kCoverWords;
    arg.num_handles = 0;  // no global handles, only the common handle
    arg.common_handle = kSubsystemCommon | kCommonId;
    if (ioctl(fd_, KCOV_REMOTE_ENABLE, &arg)) Die("KCOV_REMOTE_ENABLE");
  }
  fprintf(stderr, "[harness] pid=%d KCOV %s enabled; engine %s kernel coverage\n",
          getpid(), mode == KcovMode::kLocal ? "LOCAL" : "REMOTE",
          EngineSeesKernelCoverage() ? "SEES" : "does NOT see");
}

Kcov& Kcov::ForThisThread(KcovMode mode) {
  pid_t tid = static_cast<pid_t>(syscall(SYS_gettid));
  if (!t_kcov.kcov || t_kcov.tid != tid || t_kcov.mode != mode) {
    // First call on this thread, or we are a forked child (new tid): a
    // session KCOV_ENABLE'd by the parent belongs to the parent's task and
    // records nothing for us. Start a fresh session; the inherited mapping
    // is left alone (it belongs to the parent).
    t_kcov.kcov.release();
    t_kcov.kcov.reset(new Kcov(mode));
    t_kcov.tid = tid;
    t_kcov.mode = mode;
  }
  return *t_kcov.kcov;
}

void Kcov::Begin() { __atomic_store_n(&cover_[0], 0, __ATOMIC_RELAXED); }

std::span<const unsigned long> Kcov::End() {
  unsigned long n = __atomic_load_n(&cover_[0], __ATOMIC_RELAXED);
  if (n > kCoverWords - 1) n = kCoverWords - 1;
  return {cover_ + 1, n};
}

size_t PublishKernelFeatures(std::span<const unsigned long> pcs) {
  // HARDEN_NO_FEATURES=1: ablation switch — collect KCOV but hide it from the
  // engine, to measure how much the kernel signal actually helps.
  static const bool disabled = getenv("HARDEN_NO_FEATURES") != nullptr;
  if (disabled) return 0;
  size_t out = 0;
  uint64_t prev = 0;
  for (unsigned long pc : pcs) {
    if (out + 2 > kMaxKernelFeatures) break;
    g_kernel_features[out++] = MakeFeature(kPcDomain, Mix(pc));
    // Edge = (previous PC, this PC). Order matters, so rotate before XOR.
    g_kernel_features[out++] =
        MakeFeature(kEdgeDomain, Mix(pc ^ ((prev << 13) | (prev >> 51))));
    prev = pc;
  }
  if (TraceEnabled())
    fprintf(stderr, "[harness] kernel PCs=%zu features=%zu\n", pcs.size(), out);
  return out;
}

bool KasanReportSinceLastCall() {
  // /dev/kmsg: one record per read(). Opened per process and positioned at
  // the END of the log, so boot messages and earlier inputs do not count. The
  // file position is per open file, so a forked child must not share its
  // parent's descriptor — hence the pid check.
  static pid_t owner = 0;
  static int fd = -1;
  if (owner != getpid()) {
    fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) lseek(fd, 0, SEEK_END);
    owner = getpid();
    if (fd < 0) perror("open /dev/kmsg");
  }
  if (fd < 0) return false;

  bool found = false;
  char rec[8192];
  for (;;) {
    ssize_t n = read(fd, rec, sizeof(rec) - 1);
    if (n < 0) {
      if (errno == EPIPE) continue;  // ring buffer wrapped; keep reading
      break;                         // EAGAIN: no more records
    }
    rec[n] = '\0';
    if (strstr(rec, "BUG: KASAN")) found = true;
  }
  return found;
}

bool KasanTainted() {
  int fd = open("/proc/sys/kernel/tainted", O_RDONLY);
  if (fd < 0) return false;
  char buf[32] = {};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) return false;
  unsigned long taint = strtoul(buf, nullptr, 10);
  return taint & (1ul << 5);  // TAINT_BAD_PAGE, set by KASAN's end_report()
}

void LogReproducer(const void* data, size_t size) {
  static int fd = [] {
    const char* path = getenv("HARDEN_REPRO");
    if (!path) return -1;
    int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (f < 0) perror("open HARDEN_REPRO");
    return f;
  }();
  if (fd < 0) return;
  // Truncate-and-rewrite + fsync: the file always holds exactly the input
  // in flight, and it is on the host before a panic can lose it.
  if (lseek(fd, 0, SEEK_SET) == 0 && ftruncate(fd, 0) == 0 &&
      write(fd, data, size) >= 0)
    fsync(fd);
}

bool TraceEnabled() {
  static const bool on = getenv("HARDEN_TRACE") != nullptr;
  return on;
}

}  // namespace harden
