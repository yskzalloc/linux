// SPDX-License-Identifier: GPL-2.0

//! Rust twin of `samples/harden/remote.c` — buggy KCOV/KASAN demo with REMOTE
//! coverage (the parser runs on a workqueue kthread, not in syscall context).
//!
//! The zero-copy mmap + ioctl + injected-bug parts mirror `local.rs`; the REMOTE
//! part shows two things that were the Rust-for-Linux frontier (Part VI K5/L5 of
//! libfuzzer-study.html) and are now working:
//!
//!   1. Calling the KCOV remote FFI (`kcov_remote_start`/`kcov_remote_stop`,
//!      `kcov_common_handle`) from Rust via `kernel::bindings::`, reachable
//!      because rust/bindings/bindings_helper.h includes <linux/kcov.h>.
//!
//!   2. Dispatching to a workqueue and waiting for THAT work with `flush_work`
//!      (a reusable per-run barrier; a one-shot `Completion` fires once and then
//!      stops making the ioctl wait, starving the coverage signal).
//!
//! Built by default alongside local.rs (CONFIG_SAMPLE_RUST_HARDEN_REMOTE, which
//! defaults to CONFIG_SAMPLE_RUST_HARDEN). Pair with tools/harden/sample/remote.c.

use core::sync::atomic::{AtomicU64, Ordering};
use kernel::{
    bindings, // raw C FFI: kcov_remote_start/stop, kcov_common_handle
    fs::File,
    ioctl::_IO,
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    mm::virt::VmaNew,
    new_mutex,
    page::{Page, PAGE_SIZE},
    prelude::*,
    sync::{Arc, ArcBorrow, Mutex},
    workqueue::{self, impl_has_work, new_work, Work, WorkItem},
};

module! {
    type: HardenRemoteModule,
    name: "remote",
    authors: ["hardening tutorial"],
    description: "Buggy KCOV/KASAN hardening demo (remote coverage), in Rust",
    license: "GPL",
}

const HARDEN_RUN: u32 = _IO('H' as u32, 1);
const SLOTS: usize = 16;
const CMD_BYTES: usize = 8;
const MAX_CMDS: usize = PAGE_SIZE / CMD_BYTES - 1;
const RAW_MAGIC: u8 = 0xA5;
const OP_NOP: u8 = 0;
const OP_SET: u8 = 1;
const OP_SET_RAW: u8 = 2;

#[pin_data]
struct HardenRemoteModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<HardenDevice>,
}

impl kernel::InPlaceModule for HardenRemoteModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(MiscDeviceOptions {
                name: c"harden_remote",
            }),
        })
    }
}

#[pin_data]
struct HardenDevice {
    page: Page,
    #[pin]
    slots: Mutex<KVec<u8>>,
    /// Embedded work node so this struct can be queued on a workqueue.
    #[pin]
    work: Work<HardenDevice>,
    /// KCOV common handle installed by the harness (read in ioctl context).
    handle: AtomicU64,
}

impl_has_work! {
    impl HasWork<Self> for HardenDevice { self.work }
}

#[inline(never)]
fn harden_run(page: &[u8; PAGE_SIZE], slots: &mut KVec<u8>) {
    let count = ((page[0] as usize) | ((page[1] as usize) << 8)).min(MAX_CMDS);
    for i in 1..=count {
        let c = &page[i * CMD_BYTES..i * CMD_BYTES + CMD_BYTES];
        let (op, idx, flag, val) = (c[0], c[1] as usize, c[2], c[3]);
        match op {
            OP_NOP => {}
            OP_SET => {
                if idx < SLOTS {
                    slots[idx] = val; // SAFE
                }
            }
            OP_SET_RAW => {
                if flag == RAW_MAGIC {
                    // SAFETY: intentionally unsound OOB write — the injected bug.
                    unsafe { slots.as_mut_ptr().add(idx).write(val) };
                }
            }
            _ => return,
        }
    }
}

impl WorkItem for HardenDevice {
    type Pointer = Arc<HardenDevice>;

    fn run(this: Arc<HardenDevice>) {
        let handle = this.handle.load(Ordering::Relaxed);

        // Route this kthread's coverage back to the harness's KCOV fd.
        // SAFETY: FFI to the KCOV remote API; `handle` is the common handle the
        // harness installed via KCOV_REMOTE_ENABLE.
        unsafe { bindings::kcov_remote_start(handle) };

        let mut buf = [0u8; PAGE_SIZE];
        // SAFETY: read our whole page into a local snapshot.
        let _ = unsafe { this.page.read_raw(buf.as_mut_ptr(), 0, PAGE_SIZE) };
        {
            let mut slots = this.slots.lock();
            harden_run(&buf, &mut slots);
        }

        // SAFETY: paired with kcov_remote_start above.
        unsafe { bindings::kcov_remote_stop() };
    }
}

#[vtable]
impl MiscDevice for HardenDevice {
    type Ptr = Arc<HardenDevice>;

    fn open(_file: &File, _misc: &MiscDeviceRegistration<Self>) -> Result<Arc<HardenDevice>> {
        let page = Page::alloc_page(GFP_KERNEL | __GFP_ZERO)?;
        let mut slots = KVec::new();
        slots.resize(SLOTS, 0u8, GFP_KERNEL)?;

        Arc::pin_init(
            try_pin_init! {
                HardenDevice {
                    page: page,
                    slots <- new_mutex!(slots),
                    work <- new_work!("HardenDevice::work"),
                    handle: AtomicU64::new(0),
                }
            },
            GFP_KERNEL,
        )
    }

    fn mmap(device: ArcBorrow<'_, HardenDevice>, _file: &File, vma: &VmaNew) -> Result {
        vma.set_mixedmap().vm_insert_page(vma.start(), &device.page)
    }

    fn ioctl(
        device: ArcBorrow<'_, HardenDevice>,
        _file: &File,
        cmd: u32,
        _arg: usize,
    ) -> Result<isize> {
        if cmd != HARDEN_RUN {
            return Err(ENOTTY);
        }

        // Read the common handle the harness installed (must be in task ctx).
        // SAFETY: FFI; returns current->kcov_handle (0 if none).
        let handle = unsafe { bindings::kcov_common_handle() }.val;

        // Take an owned reference so we can hand the device to the workqueue.
        let this = Arc::from(device);
        this.handle.store(handle, Ordering::Relaxed);

        // Queue the parse onto a kworker, then block until THAT work item has
        // finished, so the harness reads complete, correctly-attributed
        // coverage every iteration (mirrors remote.c's wait_for_completion()).
        // flush_work() is reusable per call, unlike a one-shot Completion.
        let _ = workqueue::system().enqueue(this.clone());
        // SAFETY: `this.work` is our embedded work_struct; flush_work() waits
        // for it to complete if queued/running, then returns.
        let work = unsafe { Work::raw_get(core::ptr::addr_of!(this.work)) };
        unsafe { bindings::flush_work(work) };
        Ok(0)
    }
}
