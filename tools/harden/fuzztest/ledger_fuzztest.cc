// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/fuzztest/ledger_fuzztest.cc — model-based FuzzTest property
// for samples/harden/ledger.c (/dev/harden_ledger).
//
// The bug in that driver is an accounting drift: no out-of-bounds access, no
// leak, nothing for KASAN to report. A byte-array fuzzer with a crash oracle
// can reach the buggy line all day and never notice. What finds it is:
//
//   * a STATEFUL input: std::vector<std::variant<Alloc, Resize, Free>>, a
//     sequence of typed calls on ONE open file (state is per file), and
//   * a REFERENCE MODEL: a dozen lines of userspace C++ that implement the
//     ledger's documented contract. After every call the property checks the
//     kernel's return code and `used` against the model.
//
// Coverage (KCOV -> Centipede user features) gets the engine into the
// RESIZE-success path; the model decides that what happens next is wrong.
//
//   bazel-bin/ledger_fuzztest --fuzz=HardenLedger.KernelMatchesModel

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <variant>
#include <vector>

#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"
#include "kcov_feedback.h"

namespace {

using fuzztest::InRange;
using fuzztest::StructOf;
using fuzztest::VariantOf;
using fuzztest::VectorOf;

// --- driver ABI (must match samples/harden/ledger.c) ---
struct harden_ledger_op {
  uint32_t handle, size, used, pad;
};
#define LEDGER_ALLOC _IOWR('H', 0x10, struct harden_ledger_op)
#define LEDGER_RESIZE _IOWR('H', 0x11, struct harden_ledger_op)
#define LEDGER_FREE _IOWR('H', 0x12, struct harden_ledger_op)
#define LEDGER_QUERY _IOR('H', 0x13, struct harden_ledger_op)
constexpr uint32_t kSlots = 8;
constexpr uint32_t kQuota = 4096;

// --- the typed calls the engine composes ---
struct Alloc {
  uint16_t size;
};
struct Resize {
  uint8_t handle;
  uint16_t size;
};
struct Free {
  uint8_t handle;
};
using Call = std::variant<Alloc, Resize, Free>;

// --- the reference model: the driver's CONTRACT, not its code ---
struct Model {
  std::array<uint32_t, kSlots> size{};  // 0 = free slot
  uint32_t used = 0;

  // Each returns 0 or a negative errno, exactly like the ioctl should.
  int Do(const Alloc& a) {
    if (a.size > kQuota - used) return -EDQUOT;
    for (uint32_t h = 0; h < kSlots; ++h) {
      if (size[h] == 0) {
        size[h] = a.size;
        used += a.size;
        return 0;
      }
    }
    return -ENOSPC;
  }
  int Do(const Resize& r) {
    if (r.handle >= kSlots || size[r.handle] == 0) return -EBADF;
    uint32_t old = size[r.handle];
    if (r.size > old && r.size - old > kQuota - used) return -EDQUOT;
    used = used - old + r.size;
    size[r.handle] = r.size;
    return 0;
  }
  int Do(const Free& f) {
    if (f.handle >= kSlots || size[f.handle] == 0) return -EBADF;
    used -= size[f.handle];
    size[f.handle] = 0;
    return 0;
  }
};

// --- the real thing: one fresh open file per input ---
class Ledger {
 public:
  Ledger() : fd_(open("/dev/harden_ledger", O_RDWR)) {
    if (fd_ < 0) {
      perror("open /dev/harden_ledger (is harden_ledger.ko loaded?)");
      exit(1);
    }
  }
  ~Ledger() { close(fd_); }  // release() frees every object of this file

  int Do(const Alloc& a) { return Call(LEDGER_ALLOC, 0, a.size); }
  int Do(const Resize& r) { return Call(LEDGER_RESIZE, r.handle, r.size); }
  int Do(const Free& f) { return Call(LEDGER_FREE, f.handle, 0); }
  uint32_t Used() {
    harden_ledger_op op = {};
    ioctl(fd_, LEDGER_QUERY, &op);
    return op.used;
  }

 private:
  int Call(unsigned long cmd, uint32_t handle, uint32_t size) {
    harden_ledger_op op = {handle, size, 0, 0};
    return ioctl(fd_, cmd, &op) == 0 ? 0 : -errno;
  }
  int fd_;
};

const char* Name(const Call& c) {
  return std::visit(
      [](const auto& v) -> const char* {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, Alloc>) return "Alloc";
        if constexpr (std::is_same_v<T, Resize>) return "Resize";
        return "Free";
      },
      c);
}

// ---------------------------------------------------------------------------
// The property: for EVERY sequence of calls, the kernel behaves like the model
// and never charges more than the quota.
void KernelMatchesModel(const std::vector<Call>& calls) {
  Ledger kernel;
  Model model;
  harden::Kcov& kcov = harden::Kcov::ForThisThread(harden::KcovMode::kLocal);

  kcov.Begin();
  for (size_t i = 0; i < calls.size(); ++i) {
    int want = std::visit([&](const auto& c) { return model.Do(c); }, calls[i]);
    int got = std::visit([&](const auto& c) { return kernel.Do(c); }, calls[i]);
    uint32_t used = kernel.Used();

    // Security invariant first: the quota is the thing being enforced.
    ASSERT_LE(used, kQuota) << "quota bypass after call #" << i << " ("
                            << Name(calls[i]) << "): used=" << used;
    // Then full functional agreement with the contract.
    ASSERT_EQ(got, want) << "return code differs at call #" << i << " ("
                         << Name(calls[i]) << ")";
    ASSERT_EQ(used, model.used) << "ledger drift after call #" << i << " ("
                                << Name(calls[i]) << ")";
  }
  harden::PublishKernelFeatures(kcov.End());
}

FUZZ_TEST(HardenLedger, KernelMatchesModel)
    .WithDomains(VectorOf(VariantOf(
                              StructOf<Alloc>(InRange<uint16_t>(1, kQuota)),
                              StructOf<Resize>(InRange<uint8_t>(0, kSlots - 1),
                                               InRange<uint16_t>(1, kQuota)),
                              StructOf<Free>(InRange<uint8_t>(0, kSlots - 1))))
                     .WithMaxSize(12));

// The unit tests a driver author would plausibly have written. Both pass —
// each call is correct in isolation; only the SEQUENCE breaks the ledger.
TEST(HardenLedger, AllocFreeUnitTest) {
  KernelMatchesModel({Alloc{100}, Free{0}});
}
TEST(HardenLedger, AllocResizeUnitTest) {
  KernelMatchesModel({Alloc{100}, Resize{0, 200}});
}

}  // namespace
