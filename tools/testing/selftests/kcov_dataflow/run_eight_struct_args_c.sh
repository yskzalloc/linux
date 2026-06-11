#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test struct field expansion with 1-8 member structs
DIR="$(dirname "$0")"
KO="$DIR/eight_struct_args_c/eight_struct_args_c.ko"

if [ ! -f "$KO" ]; then
	echo "SKIP: $KO not found"
	echo "Build: make LLVM=1 CC=clang M=...eight_struct_args_c modules"
	exit 4
fi

OUTPUT=$(python3 "$DIR/trigger-view.py" eight_struct_args_c --ko "$KO" --raw 2>&1)
echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "Captured"; then
	WORDS=$(echo "$OUTPUT" | grep "Captured" | grep -o '[0-9]*' | head -1)
	if [ "$WORDS" -gt 100 ]; then
		echo "PASS: eight_struct_args_c captured $WORDS words"
		exit 0
	fi
fi
echo "FAIL: eight_struct_args_c insufficient capture"
exit 1
