#!/usr/bin/env bash
#
# lab.sh — build the lab kernel, and run one hands-on hardening lab.
#
#   bash lab.sh build         # build the guest kernel + the sample modules
#   bash lab.sh userspace     # pure-userspace libFuzzer warm-up (no VM)
#   bash lab.sh local         # C driver, LOCAL KCOV coverage, in the VM
#   bash lab.sh remote        # C driver, REMOTE KCOV coverage, in the VM
#   bash lab.sh rust-local    # Rust driver (same /dev node), in the VM
#   bash lab.sh rust-remote   # Rust workqueue driver, REMOTE KCOV, in the VM
#
# Run `build` once; then each lab boots virtme-ng, loads the buggy module, and
# fuzzes it until the planted out-of-bounds write trips KASAN and the guest
# panics — which is how the crash is reported across the syscall boundary.

set -euo pipefail

VENV="${VENV:-$HOME/venv-virtme}"
if [ -f "$VENV/bin/activate" ]; then
	# shellcheck disable=SC1091
	source "$VENV/bin/activate"
else
	echo "lab.sh: no virtualenv at $VENV; relying on vng/clang from PATH" >&2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLANG="${CLANG:-clang}"
RUNS="${RUNS:-2000000}"                 # override with RUNS=... bash lab.sh ...
FUZZ_FLAGS="-g -O1 -fsanitize=fuzzer,address"

usage() {
	echo "usage: bash lab.sh {build|userspace|local|remote|rust-local|rust-remote}" >&2
	echo "  env: RUNS=N  TIME=S(userspace)  HARDEN_CMP=1(compare-feedback)" >&2
	echo "       JOBS=N  NO_RUST=1  VENV=path   (build)" >&2
	exit 2
}

# ---------------------------------------------------------------------------
# build — formerly vng.sh. Regenerates the kernel config from scratch (do NOT
# run `make defconfig` first: vng seeds an essential config itself and then
# applies the --configitem overrides below) and builds the four sample modules.
# Expect 30+ minutes on a first build: KASAN, KCOV, the Rust bindings and BTF
# are all compiler-heavy.
#
# NOTE on the invocation: it is `vng --build`, not `vng build`. virtme-ng takes
# a *positional* argument as a command to execute inside a VM, so `vng build`
# would boot a guest and try to run a program called "build" (you can see it
# base64-encoded into virtme.exec= if you try it with --dry-run).
#
# Why each --configitem is here:
#   KASAN / KASAN_GENERIC   the bug ORACLE: turns the drivers' out-of-bounds
#                           write into a report. Without it the fuzzer finds
#                           coverage and no bugs.
#   KASAN_STACK=n           our planted bug is on the heap, and per-variable
#                           stack redzones are what push core files such as
#                           lib/maple_tree.c and fs/coredump.c past
#                           -Wframe-larger-than with CONFIG_WERROR=y.
#   FRAME_WARN=4096         raise what is left of that limit. Disabling
#                           FRAME_WARN entirely (=0) or turning off WERROR does
#                           not survive vng's olddefconfig; this does.
#   PANIC_ON_OOPS=y         useful in general, but NOT sufficient on its own: a
#                           KASAN report is not an "oops". run_in_guest() below
#                           therefore also boots with kasan.fault=panic, which
#                           is what actually stops the fuzzer on a finding.
#   KCOV                    the GUIDANCE signal fed back to libFuzzer through
#                           __libfuzzer_extra_counters.
#   KCOV_ENABLE_COMPARISONS KCOV_TRACE_CMP mode, for the HARDEN_CMP=1 compare
#                           replay into libFuzzer's TORC.
#   DEBUG_FS                /sys/kernel/debug/kcov.
#   SAMPLE_HARDEN=m         the two C drivers; module-only on purpose, because a
#                           KASAN panic ends the VM and you want insmod, not a
#                           30-minute rebuild, between findings.
#   SAMPLE_RUST_HARDEN=m    both Rust drivers: samples/rust/Kconfig gives
#                           SAMPLE_RUST_HARDEN_REMOTE `default SAMPLE_RUST_HARDEN`
#                           because vng's olddefconfig drops an explicit
#                           --configitem for it.
build_kernel() {
	local jobs="${JOBS:-$(nproc)}"
	local rust_items=()

	cd "$ROOT"
	command -v vng >/dev/null 2>&1 || {
		echo "lab.sh: virtme-ng (vng) not found. Install it with:" >&2
		echo "    python3 -m venv ~/venv-virtme && ~/venv-virtme/bin/pip install virtme-ng" >&2
		exit 1
	}

	if [ -z "${NO_RUST:-}" ]; then
		if make LLVM=1 rustavailable; then
			rust_items=(
				--configitem CONFIG_RUST=y
				--configitem CONFIG_SAMPLES_RUST=y
				--configitem CONFIG_SAMPLE_RUST_HARDEN=m
			)
		else
			echo "[harden] Rust unavailable — building the C labs only" >&2
		fi
	fi

	vng --build -j "$jobs" LLVM=1 \
		--configitem CONFIG_KASAN=y \
		--configitem CONFIG_KASAN_GENERIC=y \
		--configitem CONFIG_KASAN_STACK=n \
		--configitem CONFIG_FRAME_WARN=4096 \
		--configitem CONFIG_PANIC_ON_OOPS=y \
		--configitem CONFIG_KCOV=y \
		--configitem CONFIG_KCOV_ENABLE_COMPARISONS=y \
		--configitem CONFIG_DEBUG_FS=y \
		--configitem CONFIG_SAMPLES=y \
		--configitem CONFIG_SAMPLE_HARDEN=m \
		"${rust_items[@]}"

	echo
	echo "[harden] build finished; artifacts the labs need:"
	local ko
	for ko in samples/harden/harden_local.ko \
	          samples/harden/harden_remote.ko \
	          samples/rust/harden/local.ko \
	          samples/rust/harden/remote.ko; do
		if [ -e "$ko" ]; then printf '  %-40s ok\n' "$ko"
		else                  printf '  %-40s MISSING\n' "$ko"; fi
	done

	# The two hooks every lab depends on: __sanitizer_cov_trace_pc (KCOV, the
	# guidance) and __asan_report_store* (KASAN, the oracle). A kernel built
	# without them will fuzz happily and find nothing.
	if command -v llvm-nm >/dev/null 2>&1 && [ -e samples/harden/local.o ]; then
		echo "[harden] instrumentation in samples/harden/local.o:"
		llvm-nm samples/harden/local.o \
			| grep -E 'sanitizer_cov|asan_report' | sed 's/^/  /' || true
	fi
	echo
	echo "[harden] next: bash lab.sh {userspace|local|remote|rust-local|rust-remote}"
}

# Boot the built kernel and run a command string in the guest. virtme shares the
# host filesystem, so host-built binaries and the in-tree *.ko are visible.
#
# `nokaslr` stops the kernel base from moving each boot, so KCOV PCs from
# vmlinux equal their link-time addresses (addr2line -e vmlinux works directly).
# NOTE: modules are still loaded at a dynamic address even with nokaslr, so to
# symbolise coverage from our *module* you read its .text base at runtime — see
# "Symbolizing coverage under KASLR" in Part VII of libfuzzer-study.html.
run_in_guest() {
	# --rw: give the guest write-through access to the host filesystem, so the
	# harness can persist the reproducer (HARDEN_REPRO) to a host path that
	# survives the panic. This has overhead (every write crosses 9p to the
	# host); for a real campaign you would not log every input, but for this
	# practice we want to review the reproducer, so it is on by default.
	#
	# kasan.fault=panic: make a KASAN report fatal. NOTE: CONFIG_PANIC_ON_OOPS
	# alone does NOT catch KASAN reports (they are not "oops"), so without this
	# the fuzzer would keep running past the bug instead of stopping on it.
	vng --verbose --user root --rw \
		--append "nokaslr kasan.fault=panic" --exec "$1"
}

# Print a module's .text load base (needs kptr_restrict=0). Handy for turning a
# raw KCOV PC into a module-relative offset:  off=$((pc - base)).
MOD_BASE_SNIPPET='sysctl -w kernel.kptr_restrict=0 >/dev/null; \
	echo "[harden] .text base: $(cat /sys/module/${MOD:-harden_local}/sections/.text 2>/dev/null)"'

# Common guest prologue: mount debugfs (for /sys/kernel/debug/kcov) and load a
# module, then run a fuzzer binary.
kernel_lab() {
	local ko="$1" fuzzer="$2"
	if [ ! -e "$ko" ]; then
		echo "error: $ko not found — build the kernel first: bash lab.sh build" >&2
		exit 1
	fi
	local mod; mod="$(basename "${ko%.ko}")"
	# Reproducer is written here on the host; HARDEN_CMP (if set in your env)
	# is forwarded to switch the harness into KCOV comparison-feedback mode.
	local repro="$ROOT/tools/harden/repro-$mod.bin"
	rm -f "$repro"

	# Seed corpus: the reproducer log fsync()s every input (durable-on-panic,
	# but slow over 9p), so we seed a near-miss input that reaches the buggy
	# branch — the fuzzer then only has to mutate the index out of range, and
	# the crash + reproducer appear in seconds rather than minutes.
	local corpus="$ROOT/tools/harden/corpus-$mod"
	mkdir -p "$corpus"
	cp -n "$ROOT/tools/harden/sample/seeds/harden.seed" "$corpus/" 2>/dev/null || true

	# A finding panics the guest, so vng exits non-zero — that's success here,
	# not an error; `|| true` keeps `set -e` from aborting before we report.
	run_in_guest "mount -t debugfs none /sys/kernel/debug 2>/dev/null; \
		sysctl -w kernel.kptr_restrict=0 >/dev/null; \
		insmod '$ko' && echo '[harden] loaded $(basename "$ko")'; \
		echo \"[harden] $mod .text base: \$(cat /sys/module/$mod/sections/.text 2>/dev/null)\"; \
		HARDEN_REPRO='$repro' ${HARDEN_CMP:+HARDEN_CMP=1 }'$fuzzer' -runs=$RUNS -print_final_stats=1 '$corpus'" \
		|| echo "[harden] guest exited (a KASAN panic on a finding is expected)"
	if [ -s "$repro" ]; then
		echo "[harden] reproducer saved: $repro ($(stat -c%s "$repro") bytes)"
		echo "         hexdump:"; xxd "$repro" 2>/dev/null | head -2
	fi
}

PRACTICE="${1:-}"
[ -n "$PRACTICE" ] || usage

case "$PRACTICE" in
build)
	build_kernel
	;;
userspace)
	# Pure userspace: no kernel needed. -O0 keeps every guard its own
	# coverage region (see the -O1 counter-collapse note in Part VII §36).
	out="$ROOT/tools/harden/userspace/userspace"
	"$CLANG" -g -O0 -fsanitize=fuzzer,address \
		"$ROOT/tools/harden/userspace/userspace.c" -o "$out"
	echo "[harden] running userspace warm-up (expect a heap-overflow WRITE)"
	"$out" -runs="$RUNS" -max_total_time="${TIME:-30}" -print_final_stats=1
	;;
local)
	fz=/tmp/harden_local_fuzz
	"$CLANG" $FUZZ_FLAGS "$ROOT/tools/harden/sample/local.c" -o "$fz"
	kernel_lab "$ROOT/samples/harden/harden_local.ko" "$fz"
	;;
remote)
	fz=/tmp/harden_remote_fuzz
	"$CLANG" $FUZZ_FLAGS "$ROOT/tools/harden/sample/remote.c" -o "$fz"
	kernel_lab "$ROOT/samples/harden/harden_remote.ko" "$fz"
	;;
rust-local)
	# The Rust driver exposes the same /dev/harden_local node, so the C
	# harness drives it unchanged.
	fz=/tmp/harden_local_fuzz
	"$CLANG" $FUZZ_FLAGS "$ROOT/tools/harden/sample/local.c" -o "$fz"
	kernel_lab "$ROOT/samples/rust/harden/local.ko" "$fz"
	;;
rust-remote)
	# Rust REMOTE driver (workqueue + KCOV_REMOTE_ENABLE), same /dev node as
	# the C remote driver, so the C remote harness drives it unchanged.
	fz=/tmp/harden_remote_fuzz
	"$CLANG" $FUZZ_FLAGS "$ROOT/tools/harden/sample/remote.c" -o "$fz"
	kernel_lab "$ROOT/samples/rust/harden/remote.ko" "$fz"
	;;
*)
	usage
	;;
esac
