// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/fuzztest/harden_fuzztest.cc — FuzzTest harnesses for the
// shared-page drivers samples/harden/{local,remote}.c (and their Rust twins,
// which expose the same /dev nodes).
//
// Same three steps as the libFuzzer harnesses in tools/harden/sample/:
//   1. write the input into the driver's co-mapped page (zero copy),
//   2. ioctl(HARDEN_RUN) with KCOV collecting the kernel's PCs,
//   3. hand those PCs to the engine — here as Centipede user FEATURES
//      (kcov_feedback.cc), not as libFuzzer extra COUNTERS.
// What changes is the INPUT: instead of one byte array per page, the
// property takes a typed std::vector<Cmd>, and FuzzTest's StructOf/VectorOf
// domains produce only well-formed command lists.
//
// Properties (pick one with --fuzz=<Suite.Test>):
//   Harden.RawPage         bytes -> page, the libFuzzer-equivalent (local)
//   Harden.LocalCommands   typed commands, local KCOV
//   Harden.RemoteCommands  typed commands, remote KCOV (kworker)
//
// The ORACLE depends on how the guest was booted:
//   kasan.fault=panic  (the libFuzzer labs) the guest dies on the report;
//                      HARDEN_REPRO holds the page bytes.
//   kasan.fault=report (lab.sh fuzztest-* labs, with kasan_multi_shot) the
//                      kernel survives, the harness sees "BUG: KASAN" appear
//                      in /dev/kmsg and FAILS the property — so FuzzTest
//                      itself reports, confirms and saves the finding like
//                      any userspace bug.

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "kcov_feedback.h"

namespace {

using fuzztest::Arbitrary;
using fuzztest::ElementOf;
using fuzztest::StructOf;
using fuzztest::VectorOf;
using harden::KcovMode;

// --- driver ABI (must match samples/harden/local.c and remote.c) ---
#define HARDEN_RUN _IO('H', 1)
constexpr size_t kPageBytes = 4096;
constexpr size_t kCmdBytes = 8;

// One 8-byte command, minus the 4 reserved bytes the driver ignores.
struct Cmd {
  uint8_t op;    // 0 NOP, 1 SET (checked), 2 SET_RAW (the bug), 3+ = stop
  uint8_t idx;
  uint8_t flag;  // SET_RAW only writes when flag == 0xA5
  uint8_t val;
};

// The co-mapped page of one driver. Opened lazily, and again after fork():
// Centipede runs inputs in forked children of its fork server.
class Driver {
 public:
  static Driver& Get(const char* path) {
    static pid_t owner = 0;
    static Driver* d = nullptr;
    if (!d || owner != getpid()) {
      d = new Driver(path);  // intentionally leaked; lives as long as the runner
      owner = getpid();
    }
    return *d;
  }

  // Puts `n` bytes in the shared page, runs the kernel parser under KCOV,
  // publishes the kernel PCs as features. Returns true when the kernel
  // logged a KASAN report during this call (kasan.fault=report).
  bool Run(const uint8_t* bytes, size_t n, KcovMode mode) {
    if (n > kPageBytes) n = kPageBytes;
    harden::LogReproducer(bytes, n);  // durable BEFORE the kernel may panic
    memcpy(page_, bytes, n);
    memset(page_ + n, 0, kPageBytes - n);

    harden::Kcov& kcov = harden::Kcov::ForThisThread(mode);
    harden::KasanReportSinceLastCall();  // drain: start from "now"
    kcov.Begin();
    ioctl(fd_, HARDEN_RUN);  // remote: blocks until the kworker is done
    harden::PublishKernelFeatures(kcov.End());
    return harden::KasanReportSinceLastCall();
  }

 private:
  explicit Driver(const char* path) {
    fd_ = open(path, O_RDWR);
    if (fd_ < 0) {
      fprintf(stderr, "open %s: %m (is the module loaded?)\n", path);
      exit(1);
    }
    void* p = mmap(nullptr, kPageBytes, PROT_READ | PROT_WRITE, MAP_SHARED,
                   fd_, 0);
    if (p == MAP_FAILED) {
      perror("mmap driver page");
      exit(1);
    }
    page_ = static_cast<uint8_t*>(p);
  }
  int fd_ = -1;
  uint8_t* page_ = nullptr;
};

// Serialise the typed commands into the driver's wire format: a u16 LE count
// in word 0, then one 8-byte command per word.
std::vector<uint8_t> ToPage(const std::vector<Cmd>& cmds) {
  std::vector<uint8_t> page(kCmdBytes * (cmds.size() + 1), 0);
  page[0] = static_cast<uint8_t>(cmds.size() & 0xff);
  page[1] = static_cast<uint8_t>(cmds.size() >> 8);
  for (size_t i = 0; i < cmds.size(); ++i) {
    uint8_t* c = &page[(i + 1) * kCmdBytes];
    c[0] = cmds[i].op;
    c[1] = cmds[i].idx;
    c[2] = cmds[i].flag;
    c[3] = cmds[i].val;
  }
  return page;
}

void ExpectNoKasan(bool new_report, size_t n) {
  // Only reachable with kasan.fault=report: with =panic the guest is gone.
  EXPECT_FALSE(new_report)
      << "the kernel produced a KASAN report while parsing this " << n
      << "-byte page — see the guest console (dmesg) for the splat";
}

// ---------------------------------------------------------------------------
// Harden.RawPage — the libFuzzer harness, translated one-to-one.
void RawPage(const std::vector<uint8_t>& bytes) {
  bool hit = Driver::Get("/dev/harden_local")
                 .Run(bytes.data(), bytes.size(), KcovMode::kLocal);
  ExpectNoKasan(hit, bytes.size());
}
FUZZ_TEST(Harden, RawPage)
    .WithDomains(Arbitrary<std::vector<uint8_t>>().WithMaxSize(kPageBytes))
    // The same near-miss seed as tools/harden/sample/seeds/harden.seed:
    // count=1, {op=SET_RAW, idx=0, flag=0xA5, val=1}.
    .WithSeeds({{std::vector<uint8_t>{1, 0, 0, 0, 0, 0, 0, 0,
                                      2, 0, 0xA5, 1, 0, 0, 0, 0}}});

// ---------------------------------------------------------------------------
// Harden.LocalCommands / Harden.RemoteCommands — typed command lists.
//
// The domain encodes what we KNOW about the ABI (ops 0..3, at most kMaxCmds
// commands, a u16 count that always matches) and leaves what we want the
// engine to EXPLORE (idx, flag, val) Arbitrary. No seed: compare this with
// RawPage, which needed the near-miss seed to be fast.
auto CmdDomain() {
  return StructOf<Cmd>(ElementOf<uint8_t>({0, 1, 2, 3}), Arbitrary<uint8_t>(),
                       Arbitrary<uint8_t>(), Arbitrary<uint8_t>());
}

void LocalCommands(const std::vector<Cmd>& cmds) {
  std::vector<uint8_t> page = ToPage(cmds);
  bool hit = Driver::Get("/dev/harden_local")
                 .Run(page.data(), page.size(), KcovMode::kLocal);
  ExpectNoKasan(hit, page.size());
}
FUZZ_TEST(Harden, LocalCommands)
    .WithDomains(VectorOf(CmdDomain()).WithMaxSize(16));

void RemoteCommands(const std::vector<Cmd>& cmds) {
  std::vector<uint8_t> page = ToPage(cmds);
  bool hit = Driver::Get("/dev/harden_remote")
                 .Run(page.data(), page.size(), KcovMode::kRemote);
  ExpectNoKasan(hit, page.size());
}
FUZZ_TEST(Harden, RemoteCommands)
    .WithDomains(VectorOf(CmdDomain()).WithMaxSize(16));

}  // namespace
