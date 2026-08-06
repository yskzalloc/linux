#!/bin/bash
# step-by-step-file-transfer.sh
#
# Drives ksmbd (in-tree kernel SMB server) for write-side fuzzing of the
# `share` target from ksmbd-sandbox.config, uploading a file either over
# plain TCP (via smbclient) or over SMB Direct / RDMA (via mount.cifs -o
# rdma, since smbclient itself has no RDMA transport).
#
# Intended to run *inside* the vng guest, e.g. from the host:
#
#   vng --network user --exec \
#       "step-by-step-file-transfer.sh init && step-by-step-file-transfer.sh tcp <file>"
#
#   vng --network user --exec \
#       "step-by-step-file-transfer.sh init && step-by-step-file-transfer.sh rdma <file>"
#
# `--network user` is required: the RDMA path needs a real netdev
# (soft-RoCE "rxe" cannot bind to loopback) and must run as root inside the
# guest (ksmbd.mountd, modprobe, rdma link add all need it).
#
# Security note: the share this script configures is guest-accessible and
# world-writable, with no authentication. It is meant only for a disposable
# vng/qemu guest used for local LPE fuzzing of ksmbd, never for a host
# reachable from an untrusted network.

set -u

SCRIPT_NAME=$(basename "$0")

CONF=/tmp/ksmbd-sandbox-run.conf
PWDDB=/tmp/ksmbd-sandbox-run.db
MOUNTD_LOG=/tmp/ksmbd-mountd.log
SHARE_DIR=/tmp/ksmbd_share
TCP_HOST=127.0.0.1
RDMA_HOST=10.0.2.15
RDMA_IFACE=eth0
RDMA_MNT=/tmp/ksmbd-rdma-mnt
SHARE_NAME=share

die() {
	echo "${SCRIPT_NAME}: error: $*" >&2
	exit 1
}

require_root() {
	[ "$(id -u)" -eq 0 ] || die "must be run as root"
}

# Mirror the kernel's KSMBD_KCOV_IP_HANDLE (fs/smb/server/connection.h):
#   handle = 0x4b440000 | (ntohl(local_ipv4) & 0xffff)
# ksmbd's TCP receive loop and command kworker route this connection's
# server-side kcov remote coverage to this fixed handle (they are kthreads
# with no fork relationship to us, so the usual pid-derived common handle
# never reaches them). vock must KCOV_REMOTE_ENABLE the *same* handle, which
# we hand it via VOCK_KCOV_COMMON_HANDLE, otherwise the ksmbd server coverage
# is produced against a handle nobody is collecting and is silently dropped.
ksmbd_kcov_handle() {
	local ip=$1 o1 o2 o3 o4
	IFS=. read -r o1 o2 o3 o4 <<EOF
$ip
EOF
	# low 16 bits of the host-order address = (3rd octet << 8) | 4th octet
	printf '0x%08x' $(( 0x4b440000 | (((o3 & 0xff) << 8) | (o4 & 0xff)) ))
}

wait_for_port_445() {
	local i
	for i in $(seq 1 50); do
		ss -ltn 2>/dev/null | grep -q ':445 ' && return 0
		sleep 0.2
	done
	return 1
}

# ---------------------------------------------------------------------------
# init: load ksmbd, write a trimmed single-share config (mirrors the `share`
# section of ksmbd-sandbox.config: guest-ok, world-writable, force user=root),
# and start ksmbd.mountd.
# ---------------------------------------------------------------------------
cmd_init() {
	require_root

	command -v ksmbd.mountd >/dev/null 2>&1 || die "ksmbd.mountd not found (install ksmbd-tools)"
	modprobe -n ksmbd >/dev/null 2>&1 || die "ksmbd module not available"

	if ss -ltn 2>/dev/null | grep -q ':445 '; then
		echo "${SCRIPT_NAME}: ksmbd already listening on :445, reusing it"
	else
		mkdir -p "$SHARE_DIR"
		chmod 0777 "$SHARE_DIR"

		cat > "$CONF" <<EOF
[global]
	workgroup = WORKGROUP
	netbios name = FUZZHOST
	map to guest = Bad User
	guest account = nobody
	server min protocol = SMB2_10
	server max protocol = SMB3_11
	server string = ksmbdzzer
	smb2 leases = yes
	durable handles = yes
	oplocks = yes
	server multi channel support = yes
	server signing = auto
	deadtime = 0
	ipc timeout = 0
	restrict anonymous = 0

[$SHARE_NAME]
	path = $SHARE_DIR
	comment = Full feature write share
	writeable = yes
	read only = no
	guest ok = yes
	force user = root
	force group = root
	create mask = 0777
	directory mask = 0777
	force create mode = 0000
	force directory mode = 0000
	oplocks = yes
	store dos attributes = yes
	hide dot files = no
	follow symlinks = yes
	crossmnt = yes
	inherit owner = yes
EOF

		modprobe ksmbd || die "modprobe ksmbd failed"

		ksmbd.mountd -n -C "$CONF" -P "$PWDDB" > "$MOUNTD_LOG" 2>&1 &
		disown

		wait_for_port_445 || {
			cat "$MOUNTD_LOG" >&2
			die "ksmbd.mountd did not start listening on :445"
		}
	fi

	echo "${SCRIPT_NAME}: ksmbd ready, share '$SHARE_NAME' -> $SHARE_DIR"
}

# ---------------------------------------------------------------------------
# tcp <file>: upload <file> to the share over plain TCP/445 using smbclient,
# authenticating as guest (-N), the way an unauthenticated write-side fuzzer
# would reach ksmbd.
# ---------------------------------------------------------------------------
cmd_tcp() {
	local file=$1
	[ -n "${file:-}" ] || die "usage: $SCRIPT_NAME tcp <file>"
	[ -f "$file" ] || die "no such file: $file"
	command -v smbclient >/dev/null 2>&1 || die "smbclient not found"

	ss -ltn 2>/dev/null | grep -q ':445 ' || die "ksmbd is not running; run '$SCRIPT_NAME init' first"

	local base
	base=$(basename "$file")

	echo "${SCRIPT_NAME}: uploading '$file' to //$TCP_HOST/$SHARE_NAME/$base over TCP"
	# smbclient "//$TCP_HOST/$SHARE_NAME" -N -c "put $file $base"
	#
	# vock collects ksmbd's server-side coverage (fs/smb/server) through KCOV
	# remote: ksmbd routes it to the IP-derived common handle below, so we pin
	# vock's remote collector to the same handle. 'sudo env VAR=...' is needed
	# because sudo scrubs the environment otherwise.
	local handle
	handle=$(ksmbd_kcov_handle "$TCP_HOST")
	echo "${SCRIPT_NAME}: routing ksmbd TCP server coverage to kcov handle $handle"
	sudo env "VOCK_KCOV_COMMON_HANDLE=$handle" \
		/home/debian-sid/vock/vock.bin --mode kcov --kernel-src . --vmlinux vmlinux --syscall ptrace \
		smbclient "//$TCP_HOST/$SHARE_NAME" -N -c "put $file $base"
	local rc=$?
	[ $rc -eq 0 ] || die "smbclient put failed (exit $rc)"

	[ -f "$SHARE_DIR/$base" ] || die "upload reported success but $SHARE_DIR/$base is missing"
	echo "${SCRIPT_NAME}: confirmed $SHARE_DIR/$base ($(stat -c%s "$SHARE_DIR/$base") bytes)"
}

# ---------------------------------------------------------------------------
# rdma <file>: upload <file> over SMB Direct. smbclient has no RDMA
# transport, so this brings up a soft-RoCE (rxe) link on a real netdev,
# mounts the share client-side with `cifs -o rdma`, and copies the file
# through that mount -- which is what actually drives the ksmbd
# transport_rdma.c path.
# ---------------------------------------------------------------------------
cmd_rdma() {
	local file=$1
	[ -n "${file:-}" ] || die "usage: $SCRIPT_NAME rdma <file>"
	[ -f "$file" ] || die "no such file: $file"

	ss -ltn 2>/dev/null | grep -q ':445 ' || die "ksmbd is not running; run '$SCRIPT_NAME init' first"

	modprobe -n cifs >/dev/null 2>&1 || die "cifs client module not available (need CONFIG_CIFS=m, CONFIG_CIFS_SMB_DIRECT=y)"
	modprobe -n rdma_rxe >/dev/null 2>&1 || die "rdma_rxe module not available (need CONFIG_RDMA_RXE=y)"
	command -v rdma >/dev/null 2>&1 || die "rdma (iproute2) not found"

	ip link show "$RDMA_IFACE" >/dev/null 2>&1 || die "netdev $RDMA_IFACE not present; run under 'vng --network user'"
	ip link set "$RDMA_IFACE" up
	ip addr show "$RDMA_IFACE" | grep -q "$RDMA_HOST" ||
		ip addr add "$RDMA_HOST/24" dev "$RDMA_IFACE" 2>/dev/null

	modprobe rdma_rxe || die "modprobe rdma_rxe failed"
	if ! rdma link show 2>/dev/null | grep -q " netdev $RDMA_IFACE"; then
		rdma link add rxe0 type rxe netdev "$RDMA_IFACE" || die "rdma link add failed"
	fi

	modprobe cifs || die "modprobe cifs failed"

	mkdir -p "$RDMA_MNT"
	if ! mountpoint -q "$RDMA_MNT"; then
		timeout 20 mount -t cifs "//$RDMA_HOST/$SHARE_NAME" "$RDMA_MNT" \
			-o vers=3.1.1,rdma,guest,sec=none ||
			die "mount.cifs -o rdma failed; check dmesg for 'RDMA transport established'"
	fi

	local base
	base=$(basename "$file")

	echo "${SCRIPT_NAME}: uploading '$file' to //$RDMA_HOST/$SHARE_NAME/$base over SMB Direct (RDMA)"
	# timeout 30 cp "$file" "$RDMA_MNT/$base" || die "cp over RDMA mount failed"
	sudo /home/debian-sid/vock/vock.bin --mode kcov --kernel-src  . --vmlinux vmlinux cp "$file" "$RDMA_MNT/$base"
	sync

	[ -f "$SHARE_DIR/$base" ] || die "upload reported success but $SHARE_DIR/$base is missing"
	echo "${SCRIPT_NAME}: confirmed $SHARE_DIR/$base ($(stat -c%s "$SHARE_DIR/$base") bytes)"

	if dmesg | grep -q "RDMA transport established"; then
		echo "${SCRIPT_NAME}: confirmed via dmesg: RDMA transport established"
	fi
}

cmd_clean() {
	require_root
	mountpoint -q "$RDMA_MNT" 2>/dev/null && umount "$RDMA_MNT"
	pkill -f "$(command -v ksmbd.mountd 2>/dev/null || echo ksmbd.mountd)" 2>/dev/null
	for i in $(seq 1 25); do
		ss -ltn 2>/dev/null | grep -q ':445 ' || break
		sleep 0.2
	done
	modprobe -r ksmbd 2>/dev/null
	echo "${SCRIPT_NAME}: stopped ksmbd and cleaned up"
}

usage() {
	cat <<EOF
usage: $SCRIPT_NAME <init|tcp <file>|rdma <file>|clean>

  init         load ksmbd, write a config for a guest-writable share, start ksmbd.mountd
  tcp <file>   upload <file> to the share over plain TCP/445 (smbclient, guest auth)
  rdma <file>  upload <file> to the share over SMB Direct / RDMA (mount.cifs -o rdma)
  clean        stop ksmbd.mountd and unload ksmbd
EOF
}

case "${1:-}" in
init) cmd_init ;;
tcp) cmd_tcp "${2:-}" ;;
rdma) cmd_rdma "${2:-}" ;;
clean) cmd_clean ;;
*) usage; exit 1 ;;
esac
