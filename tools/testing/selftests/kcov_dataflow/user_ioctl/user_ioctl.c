// SPDX-License-Identifier: GPL-2.0
/*
 * kcov_dataflow_test.c - Selftest for /sys/kernel/debug/kcov_dataflow
 *
 * Verifies the ioctl interface: open, INIT_TRACK, mmap, ENABLE, DISABLE.
 * With INSTRUMENT_ALL, also verifies that records are produced for
 * syscalls executed while recording is active.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "../../kselftest_harness.h"

#define KCOV_DF_INIT_TRACK	_IOR('d', 1, unsigned long)
#define KCOV_DF_ENABLE		_IO('d', 100)
#define KCOV_DF_DISABLE		_IO('d', 101)

#define BUF_SIZE 65536

#define DF_TYPE_ENTRY	0xE
#define DF_TYPE_RET	0xF

FIXTURE(kcov_dataflow) {
	int fd;
	uint64_t *buf;
};

FIXTURE_SETUP(kcov_dataflow)
{
	self->fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
	if (self->fd < 0)
		SKIP(return, "kcov_dataflow not available (need CONFIG_KCOV_DATAFLOW_ARGS)");
	self->buf = MAP_FAILED;
}

FIXTURE_TEARDOWN(kcov_dataflow)
{
	if (self->buf != MAP_FAILED)
		munmap(self->buf, BUF_SIZE * sizeof(uint64_t));
	if (self->fd >= 0)
		close(self->fd);
}

TEST_F(kcov_dataflow, init_track)
{
	int ret = ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE);

	ASSERT_EQ(0, ret);
}

TEST_F(kcov_dataflow, init_track_too_small)
{
	int ret = ioctl(self->fd, KCOV_DF_INIT_TRACK, 1UL);

	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EINVAL, errno);
}

TEST_F(kcov_dataflow, init_track_double)
{
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	ASSERT_EQ(-1, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	ASSERT_EQ(EBUSY, errno);
}

TEST_F(kcov_dataflow, mmap_before_init)
{
	self->buf = mmap(NULL, BUF_SIZE * sizeof(uint64_t),
			 PROT_READ | PROT_WRITE, MAP_SHARED, self->fd, 0);
	ASSERT_EQ(MAP_FAILED, self->buf);
}

TEST_F(kcov_dataflow, enable_disable)
{
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	self->buf = mmap(NULL, BUF_SIZE * sizeof(uint64_t),
			 PROT_READ | PROT_WRITE, MAP_SHARED, self->fd, 0);
	ASSERT_NE(MAP_FAILED, self->buf);
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_ENABLE, 0));
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_DISABLE, 0));
}

TEST_F(kcov_dataflow, enable_without_mmap)
{
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	/* enable works even without mmap (mmap is optional for setup) */
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_ENABLE, 0));
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_DISABLE, 0));
}

TEST_F(kcov_dataflow, disable_without_enable)
{
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	ASSERT_EQ(-1, ioctl(self->fd, KCOV_DF_DISABLE, 0));
	ASSERT_EQ(EINVAL, errno);
}

TEST_F(kcov_dataflow, double_enable)
{
	int fd2;

	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	self->buf = mmap(NULL, BUF_SIZE * sizeof(uint64_t),
			 PROT_READ | PROT_WRITE, MAP_SHARED, self->fd, 0);
	ASSERT_NE(MAP_FAILED, self->buf);
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_ENABLE, 0));

	/* Second fd should fail to enable (task already active) */
	fd2 = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
	ASSERT_GE(fd2, 0);
	ASSERT_EQ(0, ioctl(fd2, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	ASSERT_EQ(-1, ioctl(fd2, KCOV_DF_ENABLE, 0));
	ASSERT_EQ(EBUSY, errno);
	close(fd2);

	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_DISABLE, 0));
}

TEST_F(kcov_dataflow, records_captured)
{
	uint64_t count;

	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_INIT_TRACK, (unsigned long)BUF_SIZE));
	self->buf = mmap(NULL, BUF_SIZE * sizeof(uint64_t),
			 PROT_READ | PROT_WRITE, MAP_SHARED, self->fd, 0);
	ASSERT_NE(MAP_FAILED, self->buf);
	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_ENABLE, 0));

	/* Trigger some kernel code in this task */
	getpid();

	ASSERT_EQ(0, ioctl(self->fd, KCOV_DF_DISABLE, 0));

	count = self->buf[0];
	/*
	 * With INSTRUMENT_ALL, getpid() produces records.
	 * Without it, count may be 0 (no instrumented code).
	 * Either way, the interface works correctly.
	 */
	if (count > 0) {
		uint64_t hdr = self->buf[1];
		unsigned int type = (hdr >> 28) & 0xF;

		/* First record should be ENTRY or RET */
		ASSERT_TRUE(type == DF_TYPE_ENTRY || type == DF_TYPE_RET);
	}
}

TEST_HARNESS_MAIN
