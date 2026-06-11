#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test Rust struct field expansion with 1-8 member structs
DIR="$(dirname "$0")"
KO="$DIR/eight_struct_args_rust/eight_struct_args_rust.ko"

if [ ! -f "$KO" ]; then
	echo "SKIP: $KO not found"
	echo "Build: make LLVM=1 CC=clang RUSTC=\$RUSTC M=...eight_struct_args_rust modules"
	exit 4
fi

OUTPUT=$(python3 "$DIR/trigger-view.py" eight_struct_args_rust --ko "$KO" --raw 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Captured"; then
	WORDS=$(echo "$OUTPUT" | grep "Captured" | grep -o '[0-9]*' | head -1)
	if [ "$WORDS" -gt 100 ]; then
		echo "PASS: eight_struct_args_rust captured $WORDS words"
		exit 0
	fi
fi
echo "FAIL: eight_struct_args_rust insufficient capture"
exit 1
