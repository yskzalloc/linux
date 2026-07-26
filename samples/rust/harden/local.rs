// SPDX-License-Identifier: GPL-2.0

//! Rust twin of `samples/harden/local.c` — a deliberately buggy misc device
//! for the KCOV/KASAN hardening tutorial (LOCAL coverage).
//!
//! Same shape as the C version:
//!  * userspace `mmap()`s a single page that the kernel reads from (zero copy,
//!    via `VmaNew::set_mixedmap()` + `vm_insert_page`),
//!  * `ioctl(HARDEN_RUN)` parses that page in 8-byte chunks in the ioctl's own
//!    syscall context (so plain `KCOV_ENABLE` captures the coverage),
//!  * one command opcode reaches an array write with NO bounds check — an
//!    out-of-bounds write that a coverage-guided fuzzer drives it into.
//!
//! Pair with `tools/harden/sample/local.rs` (or the C harness, which is
//! ABI-compatible: same `/dev` node name would differ, so use local.rs).

use kernel::{
    fs::File,
    ioctl::_IO,
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    mm::virt::VmaNew,
    new_mutex,
    page::{Page, PAGE_SIZE},
    prelude::*,
    sync::Mutex,
};

module! {
    type: HardenLocalModule,
    name: "local",
    authors: ["hardening tutorial"],
    description: "Buggy KCOV/KASAN hardening demo (local coverage), in Rust",
    license: "GPL",
}

/// ioctl: parse the commands currently in the shared page.
const HARDEN_RUN: u32 = _IO('H' as u32, 1);

const SLOTS: usize = 16; // tiny KASAN-guarded target
const CMD_BYTES: usize = 8;
const MAX_CMDS: usize = PAGE_SIZE / CMD_BYTES - 1;
const RAW_MAGIC: u8 = 0xA5;

// Opcodes in each 8-byte chunk: [0]=op [1]=index [2]=flag [3]=value ...
const OP_NOP: u8 = 0;
const OP_SET: u8 = 1;
const OP_SET_RAW: u8 = 2;

#[pin_data]
struct HardenLocalModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<HardenDevice>,
}

impl kernel::InPlaceModule for HardenLocalModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        // Same /dev node name as the C driver so tools/harden/sample/local.c
        // works unchanged against either module (load one at a time).
        let options = MiscDeviceOptions {
            name: c"harden_local",
        };
        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
        })
    }
}

/// Per-open device state: the shared page and the guarded target buffer.
#[pin_data]
struct HardenDevice {
    /// The one page co-mapped with userspace (zero copy).
    page: Page,
    /// The KASAN-guarded target array (an unchecked write past it is the bug).
    #[pin]
    slots: Mutex<KVec<u8>>,
}

/// The parser. Reads `page` (a snapshot of the shared page) in 8-byte chunks.
/// Marked `#[inline(never)]` so it keeps its own basic blocks in the KCOV PC
/// stream, exactly like the C version's `noinline`.
#[inline(never)]
fn harden_run(page: &[u8; PAGE_SIZE], slots: &mut KVec<u8>) {
    let count = (page[0] as usize) | ((page[1] as usize) << 8);
    let count = count.min(MAX_CMDS);

    for i in 1..=count {
        let c = &page[i * CMD_BYTES..i * CMD_BYTES + CMD_BYTES];
        let (op, idx, flag, val) = (c[0], c[1] as usize, c[2], c[3]);

        match op {
            OP_NOP => {}
            OP_SET => {
                // SAFE: bounds-checked write.
                if idx < SLOTS {
                    slots[idx] = val;
                }
            }
            OP_SET_RAW => {
                if flag == RAW_MAGIC {
                    // BUG: no bounds check. We use a raw pointer write so this
                    // is a genuine out-of-bounds *write* (safe `slots[idx]`
                    // would panic instead of corrupting memory). With `idx >=
                    // SLOTS` this writes past the KVec allocation.
                    //
                    // SAFETY: intentionally unsound — this is the injected bug.
                    unsafe {
                        slots.as_mut_ptr().add(idx).write(val);
                    }
                }
            }
            _ => return,
        }
    }
}

#[vtable]
impl MiscDevice for HardenDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, _misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let page = Page::alloc_page(GFP_KERNEL | __GFP_ZERO)?;
        let mut slots = KVec::new();
        slots.resize(SLOTS, 0u8, GFP_KERNEL)?;

        KBox::try_pin_init(
            try_pin_init! {
                HardenDevice {
                    page: page,
                    slots <- new_mutex!(slots),
                }
            },
            GFP_KERNEL,
        )
    }

    fn mmap(device: Pin<&HardenDevice>, _file: &File, vma: &VmaNew) -> Result {
        // Zero-copy: co-map our single page into the userspace VMA. Userspace
        // writes here; our ioctl reads the very same physical page.
        vma.set_mixedmap().vm_insert_page(vma.start(), &device.page)
    }

    fn ioctl(
        device: Pin<&HardenDevice>,
        _file: &File,
        cmd: u32,
        _arg: usize,
    ) -> Result<isize> {
        if cmd != HARDEN_RUN {
            return Err(ENOTTY);
        }

        // Snapshot the shared page, then parse it. (Reading into a local buffer
        // is just how we safely touch page memory in Rust; it is still the
        // shared page's live contents.)
        let mut buf = [0u8; PAGE_SIZE];
        // SAFETY: `buf` is `PAGE_SIZE` bytes and we read exactly `PAGE_SIZE`
        // from offset 0 of our own page; no concurrent writer holds the lock.
        unsafe {
            device.page.read_raw(buf.as_mut_ptr(), 0, PAGE_SIZE)?;
        }

        let mut slots = device.slots.lock();
        harden_run(&buf, &mut slots);
        Ok(0)
    }
}
