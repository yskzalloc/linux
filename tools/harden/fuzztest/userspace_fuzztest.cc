// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/fuzztest/userspace_fuzztest.cc — the FuzzTest warm-up.
//
// The SAME buggy parser as tools/harden/userspace/userspace.c, fuzzed three
// ways so you can compare what the input "type" buys you:
//
//   Userspace.Bytes       a std::string of raw bytes — the libFuzzer view.
//                         The engine must discover "HARD", version 2 and kind
//                         7 from compare feedback (trace-cmp -> TORC).
//   Userspace.Typed       typed parameters (version, kind, len, payload) with
//                         the magic fixed by the harness. The wire format is
//                         now the harness's job, not the mutator's.
//   Userspace.RoundTrip   a PROPERTY, not a crash: an encoder/decoder pair
//                         must agree. No sanitizer is involved; the oracle is
//                         the EXPECT_EQ.
//
// Build + run (see lab.sh fuzztest-userspace):
//   bazel build --config=fuzztest-experimental --config=asan :userspace_fuzztest
//   bazel-bin/userspace_fuzztest --fuzz=Userspace.Bytes --fuzz_for=30s

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

#include "fuzztest/fuzztest.h"
#include "gtest/gtest.h"

namespace {

// ---------------------------------------------------------------------------
// The code under test, verbatim from userspace.c (C++-ified casts only).
struct hdr {
  uint8_t magic[4];  // must be "HARD"
  uint8_t version;   // must be 2
  uint8_t kind;      // must be 0x7 (selects the buggy path)
  uint16_t len;      // attacker-claimed payload length (little-endian)
};

int ParseHard(const uint8_t* data, size_t size) {
  if (size < sizeof(hdr)) return 0;
  hdr h;
  memcpy(&h, data, sizeof(h));
  const uint8_t* payload = data + sizeof(h);
  size_t payload_len = size - sizeof(h);

  if (memcmp(h.magic, "HARD", 4) != 0) return 0;
  if (h.version != 2) return 0;
  if (h.kind != 0x7) return 0;

  uint8_t* buf = static_cast<uint8_t*>(malloc(payload_len ? payload_len : 1));
  if (!buf) return 0;
  if (h.len > payload_len)
    memcpy(buf, payload, h.len);  // <-- heap-buffer-overflow (WRITE)
  else
    memcpy(buf, payload, payload_len);
  free(buf);
  return 1;
}

// ---------------------------------------------------------------------------
// 1. Bytes: the libFuzzer contract, spelled as a FuzzTest property.
void Bytes(const std::string& input) {
  ParseHard(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}
FUZZ_TEST(Userspace, Bytes);  // Arbitrary<std::string>() is the default domain

// ---------------------------------------------------------------------------
// 2. Typed: the harness owns the encoding; the engine mutates fields.
std::string Encode(uint8_t version, uint8_t kind, uint16_t len,
                   const std::string& payload) {
  std::string out("HARD", 4);
  out.push_back(static_cast<char>(version));
  out.push_back(static_cast<char>(kind));
  out.push_back(static_cast<char>(len & 0xff));  // little-endian, explicitly
  out.push_back(static_cast<char>(len >> 8));
  return out + payload;
}

void Typed(uint8_t version, uint8_t kind, uint16_t len,
           const std::string& payload) {
  std::string wire = Encode(version, kind, len, payload);
  ParseHard(reinterpret_cast<const uint8_t*>(wire.data()), wire.size());
}
FUZZ_TEST(Userspace, Typed)
    .WithDomains(fuzztest::Arbitrary<uint8_t>(), fuzztest::Arbitrary<uint8_t>(),
                 fuzztest::Arbitrary<uint16_t>(),
                 fuzztest::Arbitrary<std::string>().WithMaxSize(64));

// ---------------------------------------------------------------------------
// 3. RoundTrip: a property with no memory bug at all. The decoder below has a
// planted logic bug (it reads `len` big-endian), which no sanitizer reports.
struct Msg {
  uint8_t version;
  uint8_t kind;
  uint16_t len;
};

std::optional<Msg> Decode(const std::string& wire) {
  if (wire.size() < 8 || wire.compare(0, 4, "HARD") != 0) return std::nullopt;
  Msg m;
  m.version = static_cast<uint8_t>(wire[4]);
  m.kind = static_cast<uint8_t>(wire[5]);
  // BUG: the encoder writes len little-endian; this reads it big-endian.
  // Correct for every len whose two bytes are equal (0x0000, 0x0101, ...),
  // wrong for the rest — so a unit test with len = 0 passes.
  m.len = static_cast<uint16_t>((static_cast<uint8_t>(wire[6]) << 8) |
                                static_cast<uint8_t>(wire[7]));
  return m;
}

void RoundTrip(uint8_t version, uint8_t kind, uint16_t len) {
  std::optional<Msg> m = Decode(Encode(version, kind, len, ""));
  ASSERT_TRUE(m.has_value());
  EXPECT_EQ(m->version, version);
  EXPECT_EQ(m->kind, kind);
  EXPECT_EQ(m->len, len);  // <-- the property the decoder breaks
}
FUZZ_TEST(Userspace, RoundTrip);

// A plain unit test of the same code: it passes, which is the point.
TEST(Userspace, RoundTripUnitTestMissesTheBug) { RoundTrip(2, 7, 0); }

}  // namespace
