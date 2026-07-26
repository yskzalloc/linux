// SPDX-License-Identifier: GPL-2.0
//
// userspace.rs — the Rust twin of userspace.c for the hardening tutorial.
//
// Same lesson: a *write-side* memory-safety bug hidden behind several layered
// guards, so a coverage-guided fuzzer finds it fast while a blind one cannot.
//
// This is written for `cargo-fuzz` (which links libFuzzer + AddressSanitizer):
//
//   cargo install cargo-fuzz
//   cargo fuzz init                       # once, in a crate
//   cp userspace.rs fuzz/fuzz_targets/userspace.rs
//   cargo fuzz run userspace -- -runs=2000000
//
// cargo-fuzz builds with `-Zsanitizer=address` and the same
// -Cinstrument-coverage-style SanitizerCoverage that the C example uses, so
// the mechanics (trace-cmp -> TORC -> mutation) are identical.
//
// Expected result: within a fraction of a second, an AddressSanitizer
// "heap-buffer-overflow WRITE" (from the unsafe copy below) and a crash
// reproducer.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Step 1: reject inputs too short to contain the 8-byte header. This also
    // bounds every slice access below.
    if data.len() < 8 {
        return;
    }

    // Parse the header fields out of the first 8 bytes.
    let magic = &data[0..4]; // Step 2 guard
    let version = data[4]; // Step 3 guard
    let kind = data[5]; // Step 3 guard
    // Attacker-claimed payload length (little-endian u16).
    let claimed_len = u16::from_le_bytes([data[6], data[7]]) as usize;
    let payload = &data[8..];

    // Step 2: the 4-byte magic gate. Random bytes pass this ~1 in 2^32 times;
    // trace-cmp records the failed compare and splices b"HARD" into the input,
    // so coverage-guided fuzzing clears it almost at once.
    if magic != b"HARD" {
        return;
    }

    // Step 3: two scalar guards. Together with the magic they build a funnel
    // that only a fuzzer with a coverage gradient can climb.
    if version != 2 {
        return;
    }
    if kind != 0x7 {
        return;
    }

    // Step 4: a buffer sized to the payload we ACTUALLY received (the safe
    // size).
    let mut buf = vec![0u8; payload.len().max(1)];

    // Step 5: THE BUG. This branch trusts the attacker-supplied `claimed_len`
    // instead of `payload.len()`. We use an explicit unsafe copy so the fault
    // is a genuine out-of-bounds *write* (as in the C version), which
    // AddressSanitizer catches immediately — rather than a safe-Rust panic.
    //
    // (A pure-safe version — `buf[..claimed_len].copy_from_slice(...)` — would
    // instead abort with a bounds-check panic, which libFuzzer also treats as
    // a crash; we choose the unsafe form to model real memory corruption.)
    if claimed_len > payload.len() {
        // SAFETY: intentionally unsound — writes `claimed_len` bytes into a
        // buffer only `payload.len()` bytes long. This is the injected bug.
        unsafe {
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                buf.as_mut_ptr(),
                claimed_len, // <-- heap-buffer-overflow (WRITE)
            );
        }
    } else {
        buf[..payload.len()].copy_from_slice(payload);
    }

    // Keep the optimizer from discarding the write.
    core::hint::black_box(&buf);
});
