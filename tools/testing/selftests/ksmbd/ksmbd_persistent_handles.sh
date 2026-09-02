#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Continuously Available shares and SMB3 persistent handles in ksmbd.
#
# The interesting property of a persistent handle, and the one that separates it
# from a durable handle, is that it survives the server going away.  So this
# test drives a real restart: it tears the ksmbd module down, which is what
# discards every scrap of in-memory handle state, brings it back up, and then
# asks the client to reconnect the handle it was holding.  If the reconnect
# works, the state came off disk.
#
# Requires root, the ksmbd module, and ksmbd.mountd from ksmbd-tools.  Set
# KSMBD_MOUNTD / KSMBD_ADDUSER / KSMBD_CONTROL to point at an uninstalled build.

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
source "${SCRIPT_DIR}"/../kselftest/ktap_helpers.sh

KSMBD_MOUNTD=${KSMBD_MOUNTD:-ksmbd.mountd}
KSMBD_ADDUSER=${KSMBD_ADDUSER:-ksmbd.adduser}
KSMBD_CONTROL=${KSMBD_CONTROL:-ksmbd.control}

CLIENT=${CLIENT:-${SCRIPT_DIR}/smb2_ca_client}
HOST=127.0.0.1
CA_SHARE=ksmbd_ca
PLAIN_SHARE=ksmbd_plain

WORKDIR=
SHAREDIR=

# run_test <description> <command...>
run_test() {
	local description=$1
	local out
	shift

	if out=$("$@" 2>&1); then
		ktap_test_pass "$description"
		[ -n "$out" ] && ktap_print_msg "$out"
	else
		ktap_test_fail "$description"
		[ -n "$out" ] && ktap_print_msg "$out"
	fi
}

skip_all() {
	ktap_print_header
	ktap_set_plan 0
	ktap_skip_all "$@"
	exit "$KSFT_SKIP"
}

cleanup() {
	$KSMBD_CONTROL --shutdown >/dev/null 2>&1
	# ksmbd.mountd may linger if it never saw the control request.
	pkill -f "$(basename "$KSMBD_MOUNTD")" >/dev/null 2>&1
	sleep 1
	modprobe -r ksmbd >/dev/null 2>&1
	if [ -n "$WORKDIR" ]; then
		mountpoint -q "$SHAREDIR" 2>/dev/null && umount "$SHAREDIR"
		rm -rf "$WORKDIR"
	fi
}

write_config() {
	cat > "$WORKDIR/ksmbd.conf" <<EOF
[global]
	netbios name = KSMBDCA
	server min protocol = SMB3_00
	server max protocol = SMB3_11
	map to guest = bad user
	guest account = nobody
	durable handles = yes
	smb2 leases = yes
	oplocks = yes
	server signing = disabled
	deadtime = 0

[$CA_SHARE]
	path = $SHAREDIR/ca
	writeable = yes
	guest ok = yes
	oplocks = yes
	continuous availability = yes
	create mask = 0777
	directory mask = 0777

[$PLAIN_SHARE]
	path = $SHAREDIR/plain
	writeable = yes
	guest ok = yes
	oplocks = yes
	continuous availability = no
	create mask = 0777
	directory mask = 0777
EOF
}

# Bring the kernel module and the user mode daemon up.  Used both for the
# initial start and for the simulated server crash/restart.
server_start() {
	modprobe ksmbd || return 1
	$KSMBD_MOUNTD -C "$WORKDIR/ksmbd.conf" -P "$WORKDIR/users.db" -n \
		>> "$WORKDIR/mountd.log" 2>&1 &
	# Wait for the listener rather than guessing at a sleep.
	for _ in $(seq 1 50); do
		if ss -ltn 2>/dev/null | grep -q ':445 '; then
			return 0
		fi
		sleep 0.2
	done
	return 1
}

server_stop() {
	$KSMBD_CONTROL --shutdown >/dev/null 2>&1
	pkill -f "$(basename "$KSMBD_MOUNTD")" >/dev/null 2>&1
	for _ in $(seq 1 50); do
		ss -ltn 2>/dev/null | grep -q ':445 ' || break
		sleep 0.2
	done
	# Unloading the module is what makes this a server restart and not a
	# reconnect: it destroys the global durable handle table outright.
	for _ in $(seq 1 25); do
		modprobe -r ksmbd >/dev/null 2>&1 && return 0
		sleep 0.2
	done
	return 1
}

journal_present() {
	local f
	for f in "$SHAREDIR/ca/.ksmbd-ca/handles.0" "$SHAREDIR/ca/.ksmbd-ca/handles.1"; do
		[ -s "$f" ] || continue
		# "KSCA" little endian at offset 0.
		if head -c 4 "$f" | grep -q 'KSCA'; then
			return 0
		fi
	done
	echo "no journal slot with a valid header under $SHAREDIR/ca/.ksmbd-ca" >&2
	ls -l "$SHAREDIR/ca/.ksmbd-ca" >&2 2>/dev/null
	return 1
}

# --- prerequisites -----------------------------------------------------------

[ "$(id -u)" -eq 0 ] || skip_all "this test must be run as root"

command -v modprobe >/dev/null || skip_all "modprobe not found"
modprobe -n ksmbd >/dev/null 2>&1 || skip_all "ksmbd module not available"
command -v "$KSMBD_MOUNTD" >/dev/null 2>&1 ||
	skip_all "$KSMBD_MOUNTD not found; set KSMBD_MOUNTD"
command -v "$KSMBD_ADDUSER" >/dev/null 2>&1 ||
	skip_all "$KSMBD_ADDUSER not found; set KSMBD_ADDUSER"
[ -x "$CLIENT" ] || skip_all "$CLIENT not built"
command -v ss >/dev/null 2>&1 || skip_all "ss (iproute2) not found"

if ss -ltn 2>/dev/null | grep -q ':445 '; then
	skip_all "something is already listening on port 445"
fi

WORKDIR=$(mktemp -d /tmp/ksmbd-ca.XXXXXX) || skip_all "mktemp failed"
trap cleanup EXIT
# mktemp gives 0700; the share is served as an unprivileged (guest) identity,
# which has to be able to traverse down to the share path.
chmod 0755 "$WORKDIR"

# The share needs a filesystem with the ordinary permission model and a real
# fsync.  Exporting a passthrough filesystem instead -- a 9p rw-overlay under
# /tmp in a virtme-ng guest, say -- makes the journal writes fail against the
# host's idea of who the server is, which has nothing to do with what is being
# tested here.  Mount a tmpfs so the substrate is predictable.
SHAREDIR=$WORKDIR/fs
mkdir -p "$SHAREDIR"
mount -t tmpfs -o mode=0777 tmpfs "$SHAREDIR" 2>/dev/null ||
	skip_all "cannot mount tmpfs for the test shares"

mkdir -p "$SHAREDIR/ca" "$SHAREDIR/plain"
chmod 0777 "$SHAREDIR/ca" "$SHAREDIR/plain"
write_config

# A user database has to exist even though every session here is a guest.
$KSMBD_ADDUSER -C "$WORKDIR/ksmbd.conf" -P "$WORKDIR/users.db" \
	-a ksmbd-ca-user -p ksmbd-ca-pass >/dev/null 2>&1

server_start || skip_all "cannot start ksmbd"

# --- tests -------------------------------------------------------------------

ktap_print_header
ktap_set_plan 10

# The CA share must advertise both the global persistent handle capability and
# the per-share CA capability, and it must only do so once the on-disk store
# behind it is open.
run_test "CA share advertises SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY" \
	"$CLIENT" caps "$HOST" "$CA_SHARE"

# A share without 'continuous availability' must not advertise it.
run_test "non-CA share does not advertise Continuous Availability" \
	"$CLIENT" nocaps "$HOST" "$PLAIN_SHARE"

# A persistent handle request on a non-CA share must fall back to a durable
# handle, per MS-SMB2 3.3.5.9.10.
run_test "persistent request on a non-CA share yields a durable handle" \
	"$CLIENT" nonpersistent "$HOST" "$PLAIN_SHARE" plain.dat \
	"$WORKDIR/plain.state"

# Grant a persistent handle and abandon it by dropping the connection.
run_test "server grants a persistent handle on the CA share" \
	"$CLIENT" grant "$HOST" "$CA_SHARE" ca.dat "$WORKDIR/ca.state" \
	"persistent-handle-payload"

# The grant must have hit the disk before the client was told about it.
run_test "persistent handle is recorded in the on-disk journal" \
	journal_present

# While the handle is disconnected, another client must be fenced off
# (MS-SMB2 3.3.5.9).
run_test "conflicting open is fenced with STATUS_FILE_NOT_AVAILABLE" \
	"$CLIENT" conflict "$HOST" "$CA_SHARE" ca.dat

# The state directory must not be reachable by clients.
run_test "CA state directory is not accessible to clients" \
	"$CLIENT" denied "$HOST" "$CA_SHARE" ".ksmbd-ca/handles.0"

# Reconnect across a connection loss only.  The handle is still in memory here.
run_test "handle reconnects with DH2C after connection loss" \
	"$CLIENT" reconnect "$HOST" "$CA_SHARE" ca.dat "$WORKDIR/ca.state" \
	"persistent-handle-payload"

# The one that needs the on-disk state: grant a handle, restart the server so
# that nothing is left in memory, and reconnect.
if ! "$CLIENT" grant "$HOST" "$CA_SHARE" ca2.dat "$WORKDIR/ca2.state" \
		"survives-a-restart" >/dev/null 2>&1; then
	ktap_exit_fail_msg "could not grant the handle to be recovered"
fi
if ! server_stop || ! server_start; then
	ktap_exit_fail_msg "could not restart ksmbd"
fi
run_test "handle reconnects with DH2C after a server restart" \
	"$CLIENT" reconnect "$HOST" "$CA_SHARE" ca2.dat \
	"$WORKDIR/ca2.state" "survives-a-restart"

# The other half of that: a handle the client closed must not come back.
# ca2.dat was closed by the reconnect above, so after another restart a
# different client has to be able to open it.  If the close failed to retire the
# record, recovery resurrects the handle and fences this open off.
if ! server_stop || ! server_start; then
	ktap_exit_fail_msg "could not restart ksmbd"
fi
run_test "a closed handle is not resurrected by recovery" \
	"$CLIENT" open "$HOST" "$CA_SHARE" ca2.dat

if [ "$KTAP_CNT_FAIL" -ne 0 ] && [ -s "$WORKDIR/mountd.log" ]; then
	ktap_print_msg "ksmbd.mountd said:"
	while IFS= read -r line; do
		ktap_print_msg "$line"
	done < "$WORKDIR/mountd.log"
fi

ktap_finished
