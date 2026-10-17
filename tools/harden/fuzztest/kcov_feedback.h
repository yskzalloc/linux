// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/fuzztest/kcov_feedback.h — bring-your-own-coverage for FuzzTest.
//
// The libFuzzer harnesses in tools/harden/sample/ fold KCOV PCs into
// __libfuzzer_extra_counters (an array of 8-bit counters). FuzzTest has two
// engines and only ONE of them has an equivalent seam:
//
//   * legacy in-process engine (--config=fuzztest): reads only the compiler's
//     own 8-bit counter map ("first DSO encountered"). Kernel coverage has no
//     way in. The harness still runs, but the engine is blind to the kernel.
//
//   * Centipede engine (--config=fuzztest-experimental): after every input the
//     runner scans the ELF section "__centipede_extra_features", an array of
//     64-bit FEATURES (upper 32 bits = user domain, lower 32 bits = feature
//     id, 0 = unset), adds them to the input's feature set, and zeroes them.
//
// This file implements the Centipede seam:
//   user domain 0  <- one feature per kernel PC        (like kPCs)
//   user domain 1  <- one feature per kernel PC pair   (like kPCPair / edges)
//
// It also provides the ORACLE a kernel harness can observe from userspace
// when KASAN is told not to panic (kasan.fault=report kasan_multi_shot):
//   KasanReportSinceLastCall() — scans the new /dev/kmsg records for
//                    "BUG: KASAN". With kasan_multi_shot every hit prints, so
//                    the oracle is REPEATABLE: the same input fails again
//                    when Centipede re-runs it to confirm the reproducer.
//   KasanTainted() — /proc/sys/kernel/tainted bit 5 ('B', TAINT_BAD_PAGE),
//                    set by mm/kasan/report.c. Sticky: true forever after
//                    the first report, so it cannot attribute a SECOND
//                    report to an input. Kept for comparison (Part 4).

#ifndef TOOLS_HARDEN_FUZZTEST_KCOV_FEEDBACK_H_
#define TOOLS_HARDEN_FUZZTEST_KCOV_FEEDBACK_H_

#include <cstddef>
#include <cstdint>
#include <span>

namespace harden {

enum class KcovMode {
  kLocal,   // KCOV_ENABLE: coverage of THIS thread's syscalls
  kRemote,  // KCOV_REMOTE_ENABLE + common handle: coverage of kworkers that
            // call kcov_remote_start_common() with our handle
};

// One KCOV session for the calling thread. Created lazily on first use and
// re-created automatically after fork(): Centipede's fork server runs the
// test body in a forked child, and KCOV is per-task, so the parent's fd is
// useless there.
class Kcov {
 public:
  static Kcov& ForThisThread(KcovMode mode);

  void Begin();              // reset the trace (cover[0] = 0)
  std::span<const unsigned long> End();  // the PCs collected since Begin()

 private:
  explicit Kcov(KcovMode mode);
  int fd_ = -1;
  unsigned long* cover_ = nullptr;
};

// Publish kernel PCs as Centipede user features (domains 0 and 1).
// Returns the number of feature slots written. A no-op for the engine when
// the binary is not built in Centipede mode (the section is simply ignored).
size_t PublishKernelFeatures(std::span<const unsigned long> pcs);

// True when the engine will actually consume PublishKernelFeatures().
constexpr bool EngineSeesKernelCoverage() {
#ifdef FUZZTEST_USE_CENTIPEDE
  return true;
#else
  return false;
#endif
}

// True when a KASAN report was logged since the previous call in this
// process (the first call only establishes the starting point). Requires a
// guest booted with kasan.fault=report; add kasan_multi_shot so a repeated
// bug is reported again.
bool KasanReportSinceLastCall();

// The KASAN taint bit, 'B' in /proc/sys/kernel/tainted. Sticky.
bool KasanTainted();

// HARDEN_REPRO=<path>: durably log the bytes of the input about to run, so a
// finding survives a kasan.fault=panic that kills the guest (and the
// Centipede controller with it). Same contract as the libFuzzer harnesses.
void LogReproducer(const void* data, size_t size);

// Debug aid: HARDEN_TRACE=1 prints the feature count of each input.
// Ablation: HARDEN_NO_FEATURES=1 makes PublishKernelFeatures() a no-op.
bool TraceEnabled();

}  // namespace harden

#endif  // TOOLS_HARDEN_FUZZTEST_KCOV_FEEDBACK_H_
