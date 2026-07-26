// SPDX-License-Identifier: GPL-2.0
/*
 * samples/harden/local.c — a deliberately buggy demo driver for the
 * "KCOV + libFuzzer + KASAN" hands-on hardening tutorial (LOCAL coverage).
 *
 * What it demonstrates
 * --------------------
 *  1. Zero-copy shared memory: userspace mmap()s a single page that is the
 *     *same physical page* the kernel reads from (co-mapped via
 *     remap_pfn_range). No copy_from_user; userspace writes, kernel reads.
 *
 *  2. Chunked parsing: on ioctl(HARDEN_RUN) the kernel walks the shared page
 *     one 8-byte command at a time, IN THE SYSCALL CONTEXT of the calling
 *     thread. Because the work happens on the ioctl'ing task, plain
 *     KCOV_ENABLE on that thread captures the coverage — this is the "local
 *     coverage" case (contrast samples/harden/remote.c, which runs the same
 *     parser on a kworker and therefore needs KCOV_REMOTE_ENABLE).
 *
 *  3. A write-side memory-safety bug behind an under-covered condition: one
 *     command opcode reaches an array write WITHOUT a bounds check. A
 *     coverage-guided fuzzer that drives the parser into that branch with an
 *     out-of-range index triggers a KASAN slab-out-of-bounds WRITE.
 *
 * Pair it with the userspace libFuzzer harness in
 * tools/harden/sample/local.c.
 */

#define pr_fmt(fmt) "harden_local: " fmt

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/* ioctl: parse the commands currently sitting in the shared page. */
#define HARDEN_RUN	_IO('H', 1)

/* The KASAN-guarded target array. Deliberately tiny. */
#define HARDEN_SLOTS	16

/* Each command is 8 bytes; word 0 of the page is a header (command count). */
#define HARDEN_CMD_BYTES	8
#define HARDEN_MAX_CMDS		((PAGE_SIZE / HARDEN_CMD_BYTES) - 1)

/*
 * Command byte layout (per 8-byte chunk):
 *   [0] opcode   [1] index   [2] flag   [3] value   [4..7] reserved
 */
enum {
	OP_NOP		= 0,	/* do nothing */
	OP_SET		= 1,	/* bounds-checked write (the SAFE path) */
	OP_SET_RAW	= 2,	/* unchecked write behind a flag (the BUG) */
};

/* OP_SET_RAW only writes when the flag byte matches this magic. The extra
 * condition is what makes the buggy branch "hard to reach by luck": a random
 * fuzzer rarely lands opcode==2 AND flag==0xA5 AND index>=16 together, but a
 * coverage-guided one climbs to it one comparison at a time.
 */
#define HARDEN_RAW_MAGIC	0xA5

struct harden_dev {
	struct mutex	lock;	/* serialises RUN against mmap/teardown */
	void		*page;	/* the one shared page (kernel virtual addr) */
	u8		*slots;	/* KASAN-guarded target buffer */
};

static struct harden_dev *hdev;

/*
 * The parser. Marked noinline so it is not folded into the ioctl handler and
 * gets its own basic blocks in the KCOV PC stream — that is what the fuzzer
 * sees grow as it discovers new opcodes and branches.
 */
static noinline void harden_run(struct harden_dev *d)
{
	const u8 *base = d->page;
	unsigned int i;
	u16 count;

	/* Header word: little-endian u16 count of commands that follow. */
	count = base[0] | (base[1] << 8);
	if (count > HARDEN_MAX_CMDS)
		count = HARDEN_MAX_CMDS;

	for (i = 1; i <= count; i++) {
		const u8 *c = base + i * HARDEN_CMD_BYTES;
		u8 op = c[0], idx = c[1], flag = c[2], val = c[3];

		switch (op) {
		case OP_NOP:
			break;
		case OP_SET:
			/* SAFE: the index is bounds-checked before the write. */
			if (idx < HARDEN_SLOTS)
				d->slots[idx] = val;
			break;
		case OP_SET_RAW:
			/*
			 * BUG: this path forgot the "idx < HARDEN_SLOTS" check
			 * that OP_SET has. When idx >= HARDEN_SLOTS this writes
			 * past the end of the kmalloc'd slots buffer — KASAN
			 * reports a slab-out-of-bounds WRITE.
			 */
			if (flag == HARDEN_RAW_MAGIC)
				d->slots[idx] = val;	/* <-- OOB write */
			break;
		default:
			/* Unknown opcode ends this batch. */
			return;
		}
	}
}

static long harden_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct harden_dev *d = hdev;

	if (cmd != HARDEN_RUN)
		return -ENOTTY;

	guard(mutex)(&d->lock);
	harden_run(d);
	return 0;
}

static int harden_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct harden_dev *d = hdev;
	unsigned long pfn = virt_to_phys(d->page) >> PAGE_SHIFT;

	/* Only the single shared page may be mapped, from offset 0. */
	if (vma->vm_pgoff != 0)
		return -EINVAL;
	if (vma->vm_end - vma->vm_start > PAGE_SIZE)
		return -EINVAL;

	/* Co-map the exact physical page the kernel parses from: zero copy. */
	return remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE,
			       vma->vm_page_prot);
}

static const struct file_operations harden_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= harden_ioctl,
	.mmap		= harden_mmap,
};

static struct miscdevice harden_misc = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "harden_local",
	.fops	= &harden_fops,
	.mode	= 0600,
};

static int __init harden_init(void)
{
	int ret;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (!hdev)
		return -ENOMEM;

	mutex_init(&hdev->lock);

	/* One page, zeroed, shared with userspace via mmap. */
	hdev->page = (void *)get_zeroed_page(GFP_KERNEL);
	if (!hdev->page) {
		ret = -ENOMEM;
		goto err_dev;
	}

	/* The tiny KASAN-guarded target. Its redzone catches the OOB write. */
	hdev->slots = kzalloc(HARDEN_SLOTS, GFP_KERNEL);
	if (!hdev->slots) {
		ret = -ENOMEM;
		goto err_page;
	}

	ret = misc_register(&harden_misc);
	if (ret)
		goto err_slots;

	pr_info("loaded: /dev/harden_local (slots=%d, page=%lu bytes)\n",
		HARDEN_SLOTS, PAGE_SIZE);
	return 0;

err_slots:
	kfree(hdev->slots);
err_page:
	free_page((unsigned long)hdev->page);
err_dev:
	kfree(hdev);
	hdev = NULL;
	return ret;
}

static void __exit harden_exit(void)
{
	misc_deregister(&harden_misc);
	kfree(hdev->slots);
	free_page((unsigned long)hdev->page);
	kfree(hdev);
	hdev = NULL;
}

module_init(harden_init);
module_exit(harden_exit);

MODULE_DESCRIPTION("Deliberately buggy KCOV/KASAN hardening demo (local coverage)");
MODULE_AUTHOR("hardening tutorial");
MODULE_LICENSE("GPL");
