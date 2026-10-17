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
# FuzzTest labs (Part 4 of the book; harnesses in tools/harden/fuzztest/):
#   bash lab.sh fuzztest-build      # bazel build all FuzzTest harnesses
#   bash lab.sh fuzztest-userspace  # FuzzTest warm-up, no VM
#   bash lab.sh fuzztest-local      # Harden.LocalCommands vs harden_local.ko
#   bash lab.sh fuzztest-remote     # Harden.RemoteCommands vs harden_remote.ko
#   bash lab.sh fuzztest-raw        # Harden.RawPage (bytes, like libFuzzer)
#   bash lab.sh fuzztest-ledger     # model-based property vs harden_ledger.ko
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
	echo "       bash lab.sh {fuzztest-build|fuzztest-userspace|fuzztest-local|" >&2
	echo "                    fuzztest-remote|fuzztest-raw|fuzztest-ledger}" >&2
	echo "  env: RUNS=N  TIME=S(userspace)  HARDEN_CMP=1(compare-feedback)" >&2
	echo "       JOBS=N  NO_RUST=1  VENV=path   (build)" >&2
	echo "       FUZZ_FOR=5m  ENGINE=centipede|legacy  KASAN_FAULT=report|panic" >&2
	echo "       TEST=Suite.Name (fuzztest-userspace)  REPLAY=file    (fuzztest-*)" >&2
	echo "       HARDEN_NO_FEATURES=1 (hide KCOV from the engine)  CORPUS_DB=dir" >&2
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

	local items=(
		--configitem CONFIG_KASAN=y
		--configitem CONFIG_KASAN_GENERIC=y
		--configitem CONFIG_KASAN_STACK=n
		--configitem CONFIG_FRAME_WARN=4096
		--configitem CONFIG_PANIC_ON_OOPS=y
		--configitem CONFIG_KCOV=y
		--configitem CONFIG_KCOV_ENABLE_COMPARISONS=y
		--configitem CONFIG_DEBUG_FS=y
		--configitem CONFIG_SAMPLES=y
		--configitem CONFIG_SAMPLE_HARDEN=m
		"${rust_items[@]}"
	)

	# Step 1: (re)generate .config. `vng --build` alone passes --no-update to
	# virtme-configkernel when a .config already exists, so on a tree that
	# was built before the --configitem list is silently IGNORED (and the
	# sample modules never get built). `vng --kconfig` always rewrites it.
	vng --kconfig LLVM=1 "${items[@]}"
	if ! grep -q '^CONFIG_SAMPLE_HARDEN=m' .config; then
		echo "lab.sh: CONFIG_SAMPLE_HARDEN=m did not stick in .config" >&2
		exit 1
	fi

	# Step 2: build the kernel and the modules.
	vng --build -j "$jobs" LLVM=1 "${items[@]}"

	echo
	echo "[harden] build finished; artifacts the labs need:"
	local ko
	for ko in samples/harden/harden_local.ko \
	          samples/harden/harden_remote.ko \
	          samples/harden/harden_ledger.ko \
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
	echo "         or:   bash lab.sh fuzztest-build, then fuzztest-{userspace|local|remote|raw|ledger}"
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
	#
	# KASAN_FAULT=report (the FuzzTest labs' default) keeps the kernel alive
	# after a report so the harness can turn the KASAN taint bit into a
	# property failure, and FuzzTest/Centipede report it themselves.
	#
	# --memory: virtme-ng's default guest RAM is too small for a FuzzTest
	# Centipede binary (ASan shadow + the controller/runner shared-memory
	# blobs); the first large mmap fails and the runner segfaults.
	vng --verbose --user root --rw --memory "${VM_MEMORY:-4G}" \
		--append "nokaslr kasan.fault=${KASAN_FAULT:-panic} ${KASAN_EXTRA:-}" \
		--exec "$1"
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

# ---------------------------------------------------------------------------
# FuzzTest labs. The harnesses are a Bazel workspace (FuzzTest's Centipede
# engine is only wired up in Bazel), pinned to the FuzzTest commit the book
# studies. ENGINE=centipede (default) is --config=fuzztest-experimental: the
# only engine that reads the __centipede_extra_features array, i.e. the only
# one that SEES kernel coverage. ENGINE=legacy builds --config=fuzztest, the
# in-process engine, which still runs the harness but is blind to the kernel.
FT_DIR="$ROOT/tools/harden/fuzztest"
FT_ENGINE="${ENGINE:-centipede}"
FT_OUT="$FT_DIR/out-$FT_ENGINE"

fuzztest_build() {
	command -v bazel >/dev/null 2>&1 || {
		echo "lab.sh: bazel not found. Install bazelisk as 'bazel', e.g.:" >&2
		echo "    curl -fsSLo ~/.local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/download/v1.26.0/bazelisk-linux-amd64 && chmod +x ~/.local/bin/bazel" >&2
		exit 1
	}
	local config
	case "$FT_ENGINE" in
	centipede) config="--config=fuzztest-experimental --config=asan" ;;
	legacy)    config="--config=fuzztest" ;;
	*) echo "lab.sh: ENGINE must be centipede or legacy" >&2; exit 2 ;;
	esac
	cd "$FT_DIR"
	[ -s fuzztest.bazelrc ] ||
		bazel run @com_google_fuzztest//bazel:setup_configs > fuzztest.bazelrc
	# shellcheck disable=SC2086
	bazel build $config :all
	# Copy out of bazel-bin: the binaries then survive the next build with a
	# different ENGINE, and the guest sees a plain path.
	mkdir -p "$FT_OUT"
	local t
	for t in userspace_fuzztest harden_fuzztest ledger_fuzztest; do
		install -m 0755 "bazel-bin/$t" "$FT_OUT/$t"
	done
	echo "[harden] FuzzTest ($FT_ENGINE) harnesses in $FT_OUT"
	cd "$ROOT"
}

ft_binary() {
	local b="$FT_OUT/$1"
	[ -x "$b" ] || {
		echo "error: $b not found — run: ENGINE=$FT_ENGINE bash lab.sh fuzztest-build" >&2
		exit 1
	}
	echo "$b"
}

# Boot the guest, load a module, run one FuzzTest property in fuzzing mode.
# Findings land in a corpus database on the HOST (via vng --rw), so they
# survive the VM: <db>/<binary>/workdir.000/<test>/crashes.000000/<sha1>.
# REPLAY=<that file> re-runs one finding in a fresh guest instead of fuzzing.
fuzztest_kernel_lab() {
	local ko="$1" bin="$2" test="$3"
	if [ ! -e "$ko" ]; then
		echo "error: $ko not found — build the kernel first: bash lab.sh build" >&2
		exit 1
	fi
	local mod; mod="$(basename "${ko%.ko}")"
	local db="${CORPUS_DB:-$FT_DIR/corpus-db}"
	local repro="$ROOT/tools/harden/repro-$mod-fuzztest.bin"
	mkdir -p "$db"
	rm -f "$repro"
	local run
	if [ -n "${REPLAY:-}" ]; then
		# Replay mode: the unit-test runner with one input, no engine loop.
		run="FUZZTEST_REPLAY='$REPLAY' '$bin' --gtest_filter='$test'"
	else
		run="HARDEN_REPRO='$repro' ${HARDEN_TRACE:+HARDEN_TRACE=1 }${HARDEN_NO_FEATURES:+HARDEN_NO_FEATURES=1 }'$bin' \
			--fuzz='$test' --fuzz_for='${FUZZ_FOR:-5m}' \
			--corpus_database='$db'"
	fi
	# kasan_multi_shot: report EVERY hit, not just the first since boot, so
	# the harness's /dev/kmsg oracle fires again when Centipede re-runs the
	# input to confirm it (with one-shot KASAN the re-run looks clean).
	KASAN_FAULT="${KASAN_FAULT:-report}" KASAN_EXTRA="kasan_multi_shot" run_in_guest \
		"mount -t debugfs none /sys/kernel/debug 2>/dev/null; \
		sysctl -w kernel.kptr_restrict=0 >/dev/null; \
		insmod '$ko' && echo '[harden] loaded $(basename "$ko")'; \
		echo \"[harden] $mod .text base: \$(cat /sys/module/$mod/sections/.text 2>/dev/null)\"; \
		cd '$FT_DIR'; \
		$run; \
		echo \"[harden] fuzzer exit status: \$?\"; \
		echo \"[harden] kernel taint: \$(cat /proc/sys/kernel/tainted)\"; \
		dmesg | grep -A3 'BUG: KASAN' | head -8" \
		|| echo "[harden] guest exited (with KASAN_FAULT=panic a finding ends the VM)"
	if [ -s "$repro" ]; then
		echo "[harden] last input in flight: $repro ($(stat -c%s "$repro") bytes)"
		od -An -tx1 "$repro" | head -2
	fi
	echo "[harden] corpus database: $db"
	find "$db" -path "*/${test}/crashes.*" -type f 2>/dev/null | head -5 |
		sed 's/^/  crash: /'
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
fuzztest-build)
	fuzztest_build
	;;
fuzztest-userspace)
	# No VM. Without TEST=..., runs the three Userspace.* properties in turn.
	bin="$(ft_binary userspace_fuzztest)"
	for t in ${TEST:-Userspace.Bytes Userspace.Typed Userspace.RoundTrip}; do
		echo "[harden] === $t ($FT_ENGINE engine)"
		"$bin" --fuzz="$t" --fuzz_for="${FUZZ_FOR:-60s}" \
			--corpus_database="$FT_DIR/corpus-db" || true
	done
	;;
fuzztest-local)
	fuzztest_kernel_lab "$ROOT/samples/harden/harden_local.ko" \
		"$(ft_binary harden_fuzztest)" Harden.LocalCommands
	;;
fuzztest-raw)
	fuzztest_kernel_lab "$ROOT/samples/harden/harden_local.ko" \
		"$(ft_binary harden_fuzztest)" Harden.RawPage
	;;
fuzztest-remote)
	fuzztest_kernel_lab "$ROOT/samples/harden/harden_remote.ko" \
		"$(ft_binary harden_fuzztest)" Harden.RemoteCommands
	;;
fuzztest-ledger)
	fuzztest_kernel_lab "$ROOT/samples/harden/harden_ledger.ko" \
		"$(ft_binary ledger_fuzztest)" HardenLedger.KernelMatchesModel
	;;
*)
	usage
	;;
esac
