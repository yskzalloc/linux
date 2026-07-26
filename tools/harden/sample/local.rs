// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/sample/local.rs — Rust libFuzzer harness for the harden LOCAL
// driver (C: samples/harden/local.c, Rust: samples/rust/harden/local.rs).
//
// This is the Rust twin of tools/harden/sample/local.c. Same three steps:
//   1. mmap the driver's zero-copy shared page,
//   2. collect the kernel's per-thread KCOV PCs for the parsing ioctl,
//   3. fold them into libFuzzer's __libfuzzer_extra_counters so kernel coverage
//      steers the fuzzer.
//
// Written for cargo-fuzz (which links libFuzzer + AddressSanitizer):
//   cargo install cargo-fuzz
//   # in a fuzz crate whose Cargo.toml depends on `libc` and `libfuzzer-sys`:
//   cp tools/harden/sample/local.rs fuzz/fuzz_targets/harden_local.rs
//   cargo fuzz run harden_local            # run INSIDE the vng guest
//
// The extra-counters array is exported via #[unsafe(link_section)] into the
// section libFuzzer scans (study Part II §12) — the same mechanism the C
// harness uses, just spelled in Rust.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::os::raw::{c_int, c_ulong, c_void};
use std::sync::Once;

const PAGE_BYTES: usize = 4096;
const COVER_WORDS: usize = 64 << 10;

// KCOV ioctl numbers (from include/uapi/linux/kcov.h).
const KCOV_INIT_TRACE: c_ulong = 0x80086301; // _IOR('c', 1, unsigned long)
const KCOV_ENABLE: c_ulong = 0x6364; // _IO('c', 100)
const KCOV_TRACE_PC: c_ulong = 0;
// harden driver ioctl: _IO('H', 1)
const HARDEN_RUN: c_ulong = 0x4801;

// The libFuzzer extra-counters array. Every non-zero byte is a coverage
// feature, identical in status to compiler-inserted counters.
#[unsafe(link_section = "__libfuzzer_extra_counters")]
static mut KCOV_COUNTERS: [u8; 64 << 10] = [0; 64 << 10];

extern "C" {
    fn open(path: *const u8, flags: c_int) -> c_int;
    fn ioctl(fd: c_int, req: c_ulong, ...) -> c_int;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        off: i64,
    ) -> *mut c_void;
}

const O_RDWR: c_int = 2;
const PROT_RW: c_int = 0x1 | 0x2;
const MAP_SHARED: c_int = 0x1;

struct Ctx {
    dev_fd: c_int,
    shared: *mut u8,
    cover: *mut c_ulong,
}
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

static INIT: Once = Once::new();
static mut CTX: Option<Ctx> = None;

fn setup() -> Ctx {
    unsafe {
        // 1. Open the buggy driver and co-map its page (zero copy).
        let dev_fd = open(b"/dev/harden_local\0".as_ptr(), O_RDWR);
        assert!(dev_fd >= 0, "open /dev/harden_local");
        let shared = mmap(std::ptr::null_mut(), PAGE_BYTES, PROT_RW, MAP_SHARED, dev_fd, 0);
        assert!(shared as isize != -1, "mmap device");

        // 2. Set up KCOV on this thread (local coverage).
        let kfd = open(b"/sys/kernel/debug/kcov\0".as_ptr(), O_RDWR);
        assert!(kfd >= 0, "open kcov");
        assert!(ioctl(kfd, KCOV_INIT_TRACE, COVER_WORDS as c_ulong) == 0, "KCOV_INIT");
        let cover = mmap(
            std::ptr::null_mut(),
            COVER_WORDS * std::mem::size_of::<c_ulong>(),
            PROT_RW,
            MAP_SHARED,
            kfd,
            0,
        );
        assert!(cover as isize != -1, "mmap kcov");
        assert!(ioctl(kfd, KCOV_ENABLE, KCOV_TRACE_PC) == 0, "KCOV_ENABLE");

        Ctx { dev_fd, shared: shared as *mut u8, cover: cover as *mut c_ulong }
    }
}

fn mix(mut pc: u64) -> u32 {
    pc ^= pc >> 33;
    pc = pc.wrapping_mul(0xff51afd7ed558ccd);
    pc ^= pc >> 33;
    pc as u32
}

fuzz_target!(|data: &[u8]| {
    INIT.call_once(|| unsafe { CTX = Some(setup()) });
    let ctx = unsafe { CTX.as_ref().unwrap() };

    unsafe {
        // Step 1: publish the fuzz input into the co-mapped page.
        let n = data.len().min(PAGE_BYTES);
        std::ptr::copy_nonoverlapping(data.as_ptr(), ctx.shared, n);
        if n < PAGE_BYTES {
            std::ptr::write_bytes(ctx.shared.add(n), 0, PAGE_BYTES - n);
        }

        // Step 2: reset KCOV, run the kernel parser (may KASAN-panic here).
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        *ctx.cover = 0;
        ioctl(ctx.dev_fd, HARDEN_RUN);

        // Step 3: fold kernel PCs into libFuzzer's extra counters.
        let ncov = *ctx.cover as usize;
        let counters = &mut *core::ptr::addr_of_mut!(KCOV_COUNTERS);
        for i in 1..=ncov.min(COVER_WORDS - 1) {
            let pc = *ctx.cover.add(i);
            let idx = (mix(pc as u64) as usize) % counters.len();
            counters[idx] = counters[idx].wrapping_add(1);
        }
    }
});
