#!/bin/bash
# Installs the units with the socket on port 2222 and tests the sandboxed service.
# Run as root on a disposable machine (CI), it changes the system.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL $*" >&2; journalctl -u ssh-kex-tarpit.service -u ssh-kex-tarpit.socket --no-pager >&2 || true; exit 1; }
pass() { echo "ok   $*"; }

wait_journal() {  # wait_journal PATTERN
    for _ in $(seq 50); do
        journalctl -u ssh-kex-tarpit.service -o cat --no-pager | grep -q "$1" && return
        sleep 0.1
    done
    fail "no journal line matching '$1'"
}

install -Dm755 ssh-kex-tarpit /usr/bin/ssh-kex-tarpit
install -Dm644 -t /etc/systemd/system systemd/ssh-kex-tarpit.socket systemd/ssh-kex-tarpit.service
mkdir -p /usr/share/ssh-kex-tarpit/root /etc/systemd/system/ssh-kex-tarpit.socket.d /etc/systemd/system/ssh-kex-tarpit.service.d
printf '[Socket]\nListenStream=\nListenStream=2222\n' > /etc/systemd/system/ssh-kex-tarpit.socket.d/ci.conf
printf '[Service]\nExecStart=\nExecStart=/usr/bin/ssh-kex-tarpit --delay 30 --log-after 0\n' > /etc/systemd/system/ssh-kex-tarpit.service.d/ci.conf
systemctl daemon-reload

systemd-analyze verify /etc/systemd/system/ssh-kex-tarpit.socket /etc/systemd/system/ssh-kex-tarpit.service
pass "systemd-analyze verify"

systemctl start ssh-kex-tarpit.socket
out=$(timeout 5 ssh -v -F /dev/null -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null nobody@127.0.0.1 2>&1 || true)
grep -q "remote software version OpenSSH_9.6p1" <<< "$out" || fail "no fake banner from the service: $out"
! grep -q "kex: algorithm" <<< "$out" || fail "key exchange completed"
pass "service stalls a real client"

# With --delay 30 only hangup detection can log the killed client this early.
wait_journal "^127.0.0.1: 1 connection, held [4-6]s$"
pass "closed client is logged at once"

# Two addresses of one IPv6 /64 share --max-per-ip, each is logged by its full address.
net=fd00:7a:7a:7a
if ip -6 addr add "$net::1/128" dev lo nodad 2> /dev/null && ip -6 addr add "$net::2/128" dev lo nodad; then
    python3 -I - "$net" <<'EOF' || fail "IPv6 /64 does not share --max-per-ip"
import socket, sys
def connect(src):
    return socket.create_connection((sys.argv[1] + "::1", 2222), timeout=5, source_address=(sys.argv[1] + src, 0))
held = [connect("::1") for _ in range(32)]
assert all(s.recv(64).startswith(b"SSH-2.0-") for s in held)
assert connect("::2").recv(64) == b""
EOF
    wait_journal "^$net::/64 holds 32 connections, closing its new ones"
    wait_journal "^$net::2: 0 connections, 1 refused$"
    wait_journal "^$net::1: 32 connections in [0-9]*s, held [0-9]*s in total, longest [0-9]*s$"
    ip -6 addr del "$net::1/128" dev lo
    ip -6 addr del "$net::2/128" dev lo
    pass "IPv6 /64 shares --max-per-ip, full addresses are logged"
else
    echo "skip IPv6 /64 (cannot add addresses to lo)"
fi

python3 -I -c 'import socket; s = socket.create_connection(("127.0.0.1", 2222)); s.recv(64); s.recv(64)' &
client=$!
sleep 1
systemctl stop ssh-kex-tarpit.service
wait "$client"
wait_journal "^127.0.0.1: 1 connection, held [0-9]*s (shutdown)$"
pass "held client is logged at shutdown"

probe=$(test/sandbox-probe.sh)
echo "$probe"
for expect in "blocked  socket(AF_INET)" "blocked  socket(AF_INET6)" "blocked  socket(AF_NETLINK)" \
    "blocked  socket(AF_PACKET)" "connectable unix sockets: none" "writable dirs: none" \
    "blocked  unshare(CLONE_NEWUSER)" "blocked  mount tmpfs" "blocked  setuid(0)" "blocked  ptrace(ATTACH, 1)"; do
    grep -qF "$expect" <<< "$probe" || fail "sandbox probe: missing '$expect'"
done
# Newer systemd mounts the host's os-release into RootDirectory services.
case "$(grep -o 'readable files: .*' <<< "$probe")" in
    "readable files: 0 []" | "readable files: 1 ['/run/host/.os-release-stage/os-release']") ;;
    *) fail "sandbox probe: readable files" ;;
esac
[ "$(grep -o 'visible pids: .*' <<< "$probe" | wc -w)" = 3 ] || fail "sandbox probe: sees other processes"
pass "sandbox probe"

systemd-analyze security --no-pager --threshold=10 ssh-kex-tarpit.service | tail -1
pass "systemd-analyze security <= 1.0"

echo "all system tests passed"
