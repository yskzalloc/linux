// SPDX-License-Identifier: GPL-2.0
/*
 * samples/harden/remote.c — the REMOTE-coverage twin of samples/harden/local.c.
 *
 * Everything is the same (zero-copy shared page, 8-byte chunked parser, a
 * write-side bug behind an under-covered branch) with one crucial difference:
 * the parser runs on a WORKQUEUE (a kworker kthread), NOT in the syscall
 * context of the ioctl'ing thread.
 *
 * Why that matters for coverage
 * -----------------------------
 * KCOV's normal KCOV_ENABLE only records coverage for the *current task*. Work
 * done on a kworker is a different task, so a plain KCOV_ENABLE harness would
 * see NOTHING from the parser. This is the exact situation KCOV_REMOTE_ENABLE
 * exists for. The flow (the vhost pattern) is:
 *
 *   userspace: KCOV_REMOTE_ENABLE with a non-zero `common_handle`
 *              -> the kernel saves it into current->kcov_handle
 *   driver ioctl (still in task ctx): kcov_common_handle() reads that saved
 *              handle; we stash it and hand it to the worker
 *   worker (kthread): kcov_remote_start_common(handle) ... parse ...
 *              kcov_remote_stop() — coverage now lands in the harness's fd
 *
 * Pair it with tools/harden/sample/remote.c.
 */

#define pr_fmt(fmt) "harden_remote: " fmt

#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kcov.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#define HARDEN_RUN	_IO('H', 1)

#define HARDEN_SLOTS		16
#define HARDEN_CMD_BYTES	8
#define HARDEN_MAX_CMDS		((PAGE_SIZE / HARDEN_CMD_BYTES) - 1)

enum {
	OP_NOP		= 0,
	OP_SET		= 1,
	OP_SET_RAW	= 2,
};

#define HARDEN_RAW_MAGIC	0xA5

struct harden_dev {
	struct mutex			lock;
	void				*page;
	u8				*slots;
	struct work_struct		work;
	struct completion		done;
	struct kcov_common_handle_id	kh;	/* handle for remote coverage */
};

static struct harden_dev *hdev;

/* Identical parser to local.c — the whole point is that only the *context*
 * differs, not the code, so the coverage story is a clean apples-to-apples.
 */
static noinline void harden_run(struct harden_dev *d)
{
	const u8 *base = d->page;
	unsigned int i;
	u16 count;

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
			if (idx < HARDEN_SLOTS)
				d->slots[idx] = val;		/* SAFE */
			break;
		case OP_SET_RAW:
			if (flag == HARDEN_RAW_MAGIC)
				d->slots[idx] = val;		/* BUG: OOB write */
			break;
		default:
			return;
		}
	}
}

/*
 * The worker. This runs on a kworker kthread. We bracket the parse with
 * kcov_remote_start_common()/kcov_remote_stop() so that the coverage produced
 * here is attributed to the harness that passed the matching common_handle.
 */
static void harden_work(struct work_struct *w)
{
	struct harden_dev *d = container_of(w, struct harden_dev, work);

	kcov_remote_start_common(d->kh);
	harden_run(d);
	kcov_remote_stop();

	complete(&d->done);
}

static long harden_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct harden_dev *d = hdev;

	if (cmd != HARDEN_RUN)
		return -ENOTTY;

	guard(mutex)(&d->lock);

	/*
	 * Read the common handle the harness installed via KCOV_REMOTE_ENABLE.
	 * This MUST happen in task context (here, the ioctl syscall) because it
	 * reads current->kcov_handle. We then pass it to the worker.
	 */
	d->kh = kcov_common_handle();

	reinit_completion(&d->done);
	queue_work(system_wq, &d->work);
	/* Block until the worker has finished so coverage is ready to read. */
	wait_for_completion(&d->done);
	return 0;
}

static int harden_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct harden_dev *d = hdev;
	unsigned long pfn = virt_to_phys(d->page) >> PAGE_SHIFT;

	if (vma->vm_pgoff != 0)
		return -EINVAL;
	if (vma->vm_end - vma->vm_start > PAGE_SIZE)
		return -EINVAL;

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
	.name	= "harden_remote",
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
	INIT_WORK(&hdev->work, harden_work);
	init_completion(&hdev->done);

	hdev->page = (void *)get_zeroed_page(GFP_KERNEL);
	if (!hdev->page) {
		ret = -ENOMEM;
		goto err_dev;
	}

	hdev->slots = kzalloc(HARDEN_SLOTS, GFP_KERNEL);
	if (!hdev->slots) {
		ret = -ENOMEM;
		goto err_page;
	}

	ret = misc_register(&harden_misc);
	if (ret)
		goto err_slots;

	pr_info("loaded: /dev/harden_remote (remote KCOV via workqueue)\n");
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
	cancel_work_sync(&hdev->work);
	kfree(hdev->slots);
	free_page((unsigned long)hdev->page);
	kfree(hdev);
	hdev = NULL;
}

module_init(harden_init);
module_exit(harden_exit);

MODULE_DESCRIPTION("Deliberately buggy KCOV/KASAN hardening demo (remote coverage)");
MODULE_AUTHOR("hardening tutorial");
MODULE_LICENSE("GPL");
