// SPDX-License-Identifier: GPL-2.0
//
// tools/harden/sample/remote.rs — Rust libFuzzer harness for the harden REMOTE
// driver (C: samples/harden/remote.c, Rust reference: samples/rust/harden/remote.rs).
//
// Rust twin of tools/harden/sample/remote.c. The only difference from local.rs
// is the KCOV setup: the kernel parser runs on a workqueue kthread, so we must
// use KCOV_REMOTE_ENABLE with a non-zero common handle instead of KCOV_ENABLE.
// The driver reads that handle and its worker routes coverage back to our fd.
//
// cargo-fuzz usage is the same as local.rs (run INSIDE the vng guest):
//   cp tools/harden/sample/remote.rs fuzz/fuzz_targets/harden_remote.rs
//   cargo fuzz run harden_remote

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::os::raw::{c_int, c_ulong, c_void};
use std::sync::Once;

const PAGE_BYTES: usize = 4096;
const COVER_WORDS: usize = 64 << 10;

const KCOV_INIT_TRACE: c_ulong = 0x80086301; // _IOR('c', 1, unsigned long)
const KCOV_REMOTE_ENABLE: c_ulong = 0x40188662; // _IOW('c', 102, struct kcov_remote_arg)
const KCOV_TRACE_PC: u32 = 0;
const HARDEN_RUN: c_ulong = 0x4801; // _IO('H', 1)

// Common handle: subsystem COMMON (0) so the value is just the instance id.
// Any non-zero id works for a single collecting process.
const KCOV_COMMON_ID: u64 = 0x42;

#[repr(C)]
struct KcovRemoteArg {
    trace_mode: u32,
    area_size: u32,
    num_handles: u32,
    common_handle: u64,
    // no trailing handles[]: num_handles == 0
}

#[unsafe(link_section = "__libfuzzer_extra_counters")]
static mut KCOV_COUNTERS: [u8; 64 << 10] = [0; 64 << 10];

extern "C" {
    fn open(path: *const u8, flags: c_int) -> c_int;
    fn ioctl(fd: c_int, req: c_ulong, ...) -> c_int;
    fn mmap(a: *mut c_void, l: usize, p: c_int, f: c_int, fd: c_int, o: i64) -> *mut c_void;
}

const O_RDWR: c_int = 2;
const PROT_RW: c_int = 0x3;
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
        let dev_fd = open(b"/dev/harden_remote\0".as_ptr(), O_RDWR);
        assert!(dev_fd >= 0, "open /dev/harden_remote");
        let shared = mmap(std::ptr::null_mut(), PAGE_BYTES, PROT_RW, MAP_SHARED, dev_fd, 0);
        assert!(shared as isize != -1, "mmap device");

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

        // REMOTE enable via a common handle (COMMON subsystem => handle == id).
        let arg = KcovRemoteArg {
            trace_mode: KCOV_TRACE_PC,
            area_size: COVER_WORDS as u32,
            num_handles: 0,
            common_handle: KCOV_COMMON_ID,
        };
        assert!(
            ioctl(kfd, KCOV_REMOTE_ENABLE, &arg as *const _) == 0,
            "KCOV_REMOTE_ENABLE"
        );

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
        let n = data.len().min(PAGE_BYTES);
        std::ptr::copy_nonoverlapping(data.as_ptr(), ctx.shared, n);
        if n < PAGE_BYTES {
            std::ptr::write_bytes(ctx.shared.add(n), 0, PAGE_BYTES - n);
        }

        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        *ctx.cover = 0;
        // Blocks until the worker finishes (remote.c waits for completion),
        // so `cover` is complete when we read it.
        ioctl(ctx.dev_fd, HARDEN_RUN);

        let ncov = *ctx.cover as usize;
        let counters = &mut *core::ptr::addr_of_mut!(KCOV_COUNTERS);
        for i in 1..=ncov.min(COVER_WORDS - 1) {
            let pc = *ctx.cover.add(i);
            let idx = (mix(pc as u64) as usize) % counters.len();
            counters[idx] = counters[idx].wrapping_add(1);
        }
    }
});
