#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test binderfs ioctl capture via kcov_dataflow
DIR="$(dirname "$0")"
BIN="$DIR/binderfs/binderfs_test"

if [ ! -f "$BIN" ]; then
	echo "SKIP: $BIN not found"
	echo "Build: make -C tools/testing/selftests/kcov_dataflow/binderfs"
	exit 4
fi

exec "$BIN"
