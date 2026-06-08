#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test rust_ffi_contract module capture via kcov_dataflow
DIR="$(dirname "$0")"
KO="$DIR/rust_ffi_contract/rust_ffi_contract.ko"

if [ ! -f "$KO" ]; then
	echo "SKIP: $KO not found"
	echo "Build: make LLVM=1 CC=clang M=...rust_ffi_contract modules""
	exit 4  # kselftest SKIP
fi

if [ ! -e /sys/kernel/debug/kcov_dataflow ]; then
	echo "SKIP: kcov_dataflow not available"
	exit 4
fi

OUTPUT=$(python3 "$DIR/trigger-view.py" rust_ffi_contract --ko "$KO" --raw 2>&1)
RC=$?

if [ $RC -ne 0 ]; then
	echo "FAIL: trigger-and-view exited with $RC"
	echo "$OUTPUT"
	exit 1
fi

RECORDS=$(echo "$OUTPUT" | grep -c "^\[ENTRY\]\|^\[RET")
if [ "$RECORDS" -gt 0 ]; then
	echo "PASS: captured $RECORDS records from rust_ffi_contract"
	exit 0
else
	echo "FAIL: no records captured"
	echo "$OUTPUT"
	exit 1
fi
