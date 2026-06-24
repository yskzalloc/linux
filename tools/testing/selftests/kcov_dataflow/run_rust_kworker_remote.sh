#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test kcov_df_remote_start/stop from kworker context.
#
# Prerequisites:
#   - Kernel with CONFIG_KCOV_DATAFLOW_ARGS=y, CONFIG_KCOV_DATAFLOW_RET=y, CONFIG_RUST=y
#   - Module built: make LLVM=1 CC=clang RUSTC=$RUSTC RUST_LIB_SRC=$RUST_LIB_SRC \
#       M=tools/testing/selftests/kcov_dataflow/rust_kworker_remote modules

set -e

SELFDIR="$(dirname "$(readlink -f "$0")")"
KO="$SELFDIR/rust_kworker_remote/rust_kworker_remote.ko"
TRIGGER="/sys/kernel/debug/kcov_dataflow_test/trigger_kworker_remote"
DEV="/sys/kernel/debug/kcov_dataflow"

if [ ! -f "$KO" ]; then
    echo "SKIP: $KO not found (build with CONFIG_RUST=y)"
    exit 4
fi

if [ ! -c "$DEV" ] && [ ! -f "$DEV" ]; then
    echo "SKIP: $DEV not available"
    exit 4
fi

# Use trigger-view.py for the remote capture workflow
exec python3 "$SELFDIR/trigger-view.py" rust_kworker_remote \
    --ko "$KO" --remote
