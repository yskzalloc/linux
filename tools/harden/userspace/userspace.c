// SPDX-License-Identifier: GPL-2.0
//
// userspace.c — a self-contained libFuzzer target for the hardening tutorial.
//
// Goal: show a *write-side* memory-safety bug that hides behind several
// layered conditions, so that a coverage-guided fuzzer (which sees the
// compare operands via -fsanitize-coverage=trace-cmp) finds it quickly while
// a blind random fuzzer essentially never would.
//
// Build & run (uses the clang you built for this project):
//   clang -g -O1 -fsanitize=fuzzer,address userspace.c -o userspace
//   ./userspace -runs=2000000
//
// Expected result: within a fraction of a second libFuzzer prints a
// "heap-buffer-overflow WRITE" report from AddressSanitizer and writes a
// crash-<sha1> reproducer.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// A tiny wire format. The header is deliberately small and every field is a
// separate guard, so each one is one comparison the fuzzer must satisfy.
struct hdr {
	uint8_t  magic[4]; // Step 2 guard: must be "HARD"
	uint8_t  version;  // Step 3 guard: must be 2
	uint8_t  kind;     // Step 3 guard: must be 0x7 (selects the buggy path)
	uint16_t len;      // attacker-claimed payload length (little-endian)
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	// Step 1: reject inputs too short to even contain the header. This is
	// the cheap early-out every parser has; it also bounds all the reads
	// below.
	if (size < sizeof(struct hdr))
		return 0;

	struct hdr h;
	memcpy(&h, data, sizeof(h)); // copy out to avoid unaligned field access
	const uint8_t *payload = data + sizeof(h);
	size_t payload_len = size - sizeof(h);

	// Step 2: a 4-byte magic gate. Uniform random bytes satisfy this only
	// ~1 in 2^32 tries. With trace-cmp, libFuzzer observes the failed
	// memcmp, records ("HARD", <your bytes>) in its table of recent
	// compares, and splices "HARD" straight into the input — so this gate
	// falls almost immediately. This single line is the clearest argument
	// for *why* coverage-guided fuzzing beats random fuzzing.
	if (memcmp(h.magic, "HARD", 4) != 0)
		return 0;

	// Step 3: two more scalar guards. Each is another comparison the
	// value-profile "gradient" helps the fuzzer climb. Together they make
	// the buggy branch statistically unreachable by luck alone.
	if (h.version != 2)
		return 0;
	if (h.kind != 0x7)
		return 0;

	// Step 4: allocate a buffer sized to the payload we ACTUALLY received.
	// This is the correct, safe size.
	uint8_t *buf = malloc(payload_len ? payload_len : 1);
	if (!buf)
		return 0;

	// Step 5: THE BUG. In this branch the code trusts the attacker-supplied
	// h.len instead of the real payload_len. When the claimed length is
	// larger than what we allocated, this memcpy writes past the end of the
	// heap buffer — a classic out-of-bounds *write*. AddressSanitizer turns
	// that silent corruption into an immediate, reproducible crash.
	//
	// Note how much had to line up to get here: 4 magic bytes, a version, a
	// kind, and then h.len > payload_len. That funnel is exactly what makes
	// coverage guidance (not brute force) the thing that finds this.
	if (h.len > payload_len)
		memcpy(buf, payload, h.len); // <-- heap-buffer-overflow (WRITE)
	else
		memcpy(buf, payload, payload_len);

	free(buf);
	return 0;
}
