#!/bin/bash
# Unprivileged tests with real ssh clients. Needs python3, ssh and systemd-socket-activate.
# PYTHON selects the interpreter (default python3).
set -euo pipefail
cd "$(dirname "$0")/.."
py=${PYTHON:-python3}
work=$(mktemp -d)
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT

fail() { echo "FAIL $*" >&2; for f in "$work"/*; do echo "== $f" >&2; cat "$f" >&2; done; exit 1; }
pass() { echo "ok   $*"; }
skip() { echo "skip $*"; }

free_port() {  # free_port [COUNT]: COUNT different free ports
    "$py" -I -c 'import socket, sys
socks = [socket.socket() for _ in range(int(sys.argv[1]))]
for s in socks:
    s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in socks))' "${1:-1}"
}

launch() {  # launch NAME "ADDR..." SCRIPT ARGS..., sets $name and $pid. NOFILE lowers the open file limit.
    name=$1
    local addr addrs listen=()
    read -ra addrs <<< "$2"
    for addr in "${addrs[@]}"; do listen+=(-l "$addr"); done
    shift 2
    (
        [ -z "${NOFILE:-}" ] || ulimit -n "$NOFILE"
        exec systemd-socket-activate "${listen[@]}" "$py" -IuS "$@"
    ) > "$work/$name.log" 2>&1 &
    pid=$!
    pids+=("$pid")
    for _ in $(seq 50); do
        [ "$(grep -c "^Listening on" "$work/$name.log" 2> /dev/null)" = $((${#listen[@]} / 2)) ] && return
        sleep 0.1
    done
    fail "tarpit $name did not start"
}

start() {  # start NAME SCRIPT ARGS..., listens on 127.0.0.1:$port
    local n=$1
    shift
    port=$(free_port)
    launch "$n" "127.0.0.1:$port" "$@"
}

ssh_v() {  # ssh_v SECONDS, output in $work/$name.ssh, exit status in $ssh_rc (124: still connected)
    ssh_rc=0
    timeout "$1" ssh -v -F /dev/null -p "$port" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null nobody@127.0.0.1 > "$work/$name.ssh" 2>&1 || ssh_rc=$?
}

wait_log() {  # wait_log PATTERN SECONDS
    for _ in $(seq $(($2 * 10))); do
        grep -q "$1" "$work/$name.log" && return
        sleep 0.1
    done
    fail "$name: no log line matching '$1'"
}

patched() {  # patched FILE ASSIGNMENT: copy of the tarpit with another value for a constant
    "$py" -I - ssh-kex-tarpit "$1" "$2" <<'EOF'
import sys
src = open(sys.argv[1]).read()
anchor = "PADDING = 4 + -(5 + 17 + len(KEXINIT_TAIL) + 4) % 8\n"
assert anchor in src
open(sys.argv[2], "w").write(src.replace(anchor, anchor + sys.argv[3] + "\n"))
EOF
}

knock() {  # knock SOURCE SECONDS [COUNT]: connections from SOURCE, one after another, each open for SECONDS
    "$py" -I - "$port" "$@" <<'EOF'
import socket, sys, time
for _ in range(int(sys.argv[4]) if len(sys.argv) > 4 else 1):
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5, source_address=(sys.argv[2], 0))
    assert s.recv(64).startswith(b"SSH-2.0-")
    time.sleep(float(sys.argv[3]))
    s.close()
EOF
}

echo "python: $("$py" --version)"
"$py" -I -c 'import ast, sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]' ssh-kex-tarpit test/sandbox-probe.py
pass "syntax"

"$py" -IuS ssh-kex-tarpit --help > /dev/null
for args in "--delay 0" "--delay nan" "--delay inf" "--max-clients 0" "--max-clients 1.5" "--max-per-ip 0" \
    "--log-after -1" "--log-after nan" "--version-line foo"; do
    rc=0
    # shellcheck disable=SC2086
    "$py" -IuS ssh-kex-tarpit $args 2> /dev/null || rc=$?
    [ "$rc" = 2 ] || fail "accepted $args (exit $rc)"
done
pass "option validation"

rc=0
"$py" -IuS ssh-kex-tarpit 2> "$work/nosockets.err" || rc=$?
[ "$rc" = 1 ] || fail "start without sockets exited $rc"
grep -q "no listening sockets" "$work/nosockets.err" || fail "start without sockets: wrong message"
pass "refuses to start without sockets"

start stall ssh-kex-tarpit --delay 1 --log-after 0
ssh_v 5
grep -q "remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.20" "$work/stall.ssh" || fail "no fake banner"
grep -q "SSH2_MSG_KEXINIT sent" "$work/stall.ssh" || fail "client did not start key exchange"
! grep -q "kex: algorithm" "$work/stall.ssh" || fail "key exchange completed, tarpit did not stall"
pass "client sees OpenSSH banner and stalls in key exchange"
wait_log "^127.0.0.1: 1 connection, held [0-9]*s$" 5
pass "disconnect is logged"

# With --delay 60 only hangup detection can log these within seconds.
start hangup ssh-kex-tarpit --delay 60 --log-after 0
"$py" -I - "$port" <<'EOF'
import socket, struct, sys, time
addr = ("127.0.0.1", int(sys.argv[1]))
fin = socket.create_connection(addr, timeout=5)
assert fin.recv(64).startswith(b"SSH-2.0-")
fin.close()
time.sleep(0.5)
rst = socket.create_connection(addr, timeout=5)
assert rst.recv(64).startswith(b"SSH-2.0-")
rst.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
rst.close()
EOF
for _ in $(seq 30); do
    [ "$(grep -c "^127.0.0.1: 1 connection, held [01]s$" "$work/hangup.log")" = 2 ] && break
    sleep 0.1
done
ssh_v 2
for _ in $(seq 30); do
    [ "$(grep -c "^127.0.0.1: 1 connection, held [0-3]s$" "$work/hangup.log")" = 3 ] && break
    sleep 0.1
done
[ "$(grep -c "^127.0.0.1: 1 connection, held [0-3]s$" "$work/hangup.log")" = 3 ] || fail "closed clients were not logged at once"
pass "closed clients are logged at once (FIN, RST, ssh)"

start group ssh-kex-tarpit --delay 60 --log-after 3
knock 127.0.0.1 0 50
knock 127.0.0.2 0
knock 127.0.0.1 1
! grep -q "^127.0.0.[12]: " "$work/group.log" || fail "address logged before --log-after"
wait_log "^127.0.0.1: 51 connections in [0-9]*s, held [0-9]*s in total, longest [0-9]*s$" 5
wait_log "^127.0.0.2: 1 connection, held 0s$" 1
[ "$(grep -c "^127.0.0.[12]: " "$work/group.log")" = 2 ] || fail "more than one line per address"
pass "one line per address, --log-after seconds after it left"

patched "$work/short-visit" "VISIT_MAX = 2"
start visit "$work/short-visit" --delay 60 --log-after 60
knock 127.0.0.1 0.4 8
wait_log "^127.0.0.1: [4-7] connections in [2-3]s, held [1-3]s in total, longest [01]s\(, 1 still held\)\?$" 1
[ "$(grep -c "^127.0.0.1: " "$work/visit.log")" = 1 ] || fail "address that keeps coming logged more than once"
pass "an address that keeps coming is logged every VISIT_MAX seconds"

patched "$work/hold-visit" "VISIT_MAX = 1"
start hold "$work/hold-visit" --delay 60 --log-after 60
knock 127.0.0.1 2.6
[ "$(grep -c "^127.0.0.1: 0 connections, 1 still held$" "$work/hold.log")" = 2 ] || fail "held connection not logged every VISIT_MAX"
pass "an address that only holds a connection is logged every VISIT_MAX seconds"

patched "$work/small-table" "GONE_MAX = 1"
start table "$work/small-table" --delay 60 --log-after 2
knock 127.0.0.1 0
knock 127.0.0.2 0
knock 127.0.0.3 0
wait_log "^2 other addresses: 2 connections, held 0s in total$" 4
wait_log "^127.0.0.3: 1 connection, held 0s$" 2
! grep -q "^127.0.0.[12]: " "$work/table.log" || fail "address past GONE_MAX got its own line"
pass "addresses past GONE_MAX share one line"

patched "$work/small-quota" "GONE_MAX = 1; VISIT_MAX = 1"
start quota "$work/small-quota" --delay 60 --log-after 4
knocks=()
for src in 127.0.0.1 127.0.0.2 127.0.0.3; do
    knock "$src" 1.3 &
    knocks+=($!)
done
wait "${knocks[@]}"
# The three held connections are logged together after VISIT_MAX: one line, the rest to "other addresses".
wait_log "^4 other addresses: 2 connections, held [2-3]s in total$" 6
wait_log "^127.0.0.[123]: 1 connection, held 1s$" 2
[ "$(grep -c "^127.0.0.[123]: 0 connections, 1 still held$" "$work/quota.log")" = 1 ] || fail "more than GONE_MAX address lines per --log-after"
pass "address lines past GONE_MAX per --log-after share one line"

start version ssh-kex-tarpit --delay 1 --version-line "SSH-2.0-Test_1.0"
ssh_v 3
grep -q "remote software version Test_1.0" "$work/version.ssh" || fail "--version-line ignored"
pass "--version-line"

# A short declared packet, sent at full speed: a real client must accept the filled KEXINIT and wait for the reply.
patched "$work/short-kexinit" "PACKET_SIZE = 1536"
start kexinit "$work/short-kexinit" --delay 0.001 --log-after 0
ssh_v 10
grep -q "kex: algorithm: " "$work/kexinit.ssh" || fail "client rejected the KEXINIT"
grep -q "kex: host key algorithm: " "$work/kexinit.ssh" || fail "client rejected the KEXINIT host key list"
grep -q "expecting SSH2_MSG_KEX_ECDH_REPLY" "$work/kexinit.ssh" || fail "client does not wait for the reply"
[ "$ssh_rc" = 124 ] || fail "client left during the reply (exit $ssh_rc)"
wait_log "^127.0.0.1: 1 connection, held [0-9]*s$" 3
pass "KEXINIT is valid, client waits for the reply ($(grep -o 'kex: algorithm: .*' "$work/kexinit.ssh"))"

patched "$work/short-packet" "PACKET_SIZE = 1536"
start packet "$work/short-packet" --delay 0.001 --log-after 0
"$py" -I - "$port" <<'EOF' || fail "wrong packets"
import socket, struct, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=30)
data = s.recv(65536)
s.settimeout(1)
try:
    while True:
        chunk = s.recv(65536)
        assert chunk, "connection closed"
        data += chunk
except socket.timeout:
    pass
banner, _, rest = data.partition(b"\r\n")
assert banner.startswith(b"SSH-2.0-"), banner
assert len(rest) == 1536 + 1535, len(rest)
kexinit, reply = rest[:1536], rest[1536:]
length, padding, msg = struct.unpack(">IBB", kexinit[:6])
assert (length, msg) == (1532, 20) and 4 <= padding <= 11, (length, padding, msg)
pos = 22
lists = []
for _ in range(10):
    n = struct.unpack(">I", kexinit[pos:pos + 4])[0]
    lists.append(kexinit[pos + 4:pos + 4 + n])
    pos += 4 + n
names = lists[9].split(b",")
assert len(names) > 16 and all(n.isalpha() and n.islower() for n in names), lists[9]
assert kexinit[pos:pos + 5] == bytes(5), "first_kex_packet_follows and reserved"
assert pos + 5 + padding == 1536, "padding"
assert struct.unpack(">IBB", reply[:6]) == (1532, padding, 31), reply[:6]
assert len(set(reply[6:])) > 16, "reply bytes are not random"
EOF
wait_log "^127.0.0.1: 1 connection, held [0-9]*s$" 3
pass "KEXINIT padded with language names, then a reply without its last byte"

# A client that is gone without a FIN (lo taken down) is found by keepalive. Needs a user and network namespace.
if unshare -rn ip link set lo up 2> /dev/null; then
    patched "$work/keepalive" "PACKET_SIZE = 1536; KEEPALIVE = (1, 1, 1)"
    unshare -rn "$py" -I - "$work/keepalive" "$py" <<'EOF' > "$work/keepalive.log" 2>&1 || fail "vanished client was not noticed"
import select, socket, subprocess, sys, time
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
tarpit = subprocess.Popen(["systemd-socket-activate", "-l", "127.0.0.1:2222", sys.argv[2], "-IuS", sys.argv[1],
                           "--delay", "0.001", "--log-after", "0"], stdout=subprocess.PIPE, text=True)
try:
    # systemd-socket-activate starts the tarpit on the first connection.
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", 2222), timeout=30)
            break
        except ConnectionRefusedError:
            time.sleep(0.1)
    assert s.recv(64).startswith(b"SSH-2.0-")
    s.settimeout(1)
    try:
        while s.recv(65536):
            pass
    except socket.timeout:
        pass
    subprocess.run(["ip", "link", "set", "lo", "down"], check=True)
    deadline = time.monotonic() + 10
    line = ""
    while not line.startswith("127.0.0.1: 1 connection, held "):
        if not select.select([tarpit.stdout], [], [], max(0, deadline - time.monotonic()))[0]:
            sys.exit("no log line")
        line = tarpit.stdout.readline()
        if not line:
            sys.exit("tarpit exited")
        print(line, end="")
finally:
    tarpit.terminate()
EOF
    pass "a client that vanished is found by keepalive"
else
    skip "keepalive (no user and network namespace here)"
fi

start clients ssh-kex-tarpit --delay 1 --max-clients 1
"$py" -I - "$port" <<'EOF' || fail "connection over --max-clients was not closed"
import socket, sys, time
addr = ("127.0.0.1", int(sys.argv[1]))
for _ in range(3):
    held = socket.create_connection(addr, timeout=5)
    assert held.recv(64).startswith(b"SSH-2.0-")
    extra = socket.create_connection(addr, timeout=5)
    assert extra.recv(64) == b""
    held.close()
    time.sleep(0.3)
EOF
wait_log "^1 clients held, closing new connections" 2
[ "$(grep -c "^1 clients held" "$work/clients.log")" = 1 ] || fail "limit message repeated within --log-after"
pass "--max-clients, its message comes once per --log-after"

start per-ip ssh-kex-tarpit --delay 1 --max-per-ip 2 --log-after 0
"$py" -I - "$port" <<'EOF' || fail "connection over --max-per-ip was not closed"
import socket, sys, time
addr = ("127.0.0.1", int(sys.argv[1]))
held = [socket.create_connection(addr, timeout=5) for _ in range(2)]
assert all(s.recv(64).startswith(b"SSH-2.0-") for s in held)
extra = socket.create_connection(addr, timeout=5)
assert extra.recv(64) == b""
held[0].close()
time.sleep(0.5)
again = socket.create_connection(addr, timeout=5)
assert again.recv(64).startswith(b"SSH-2.0-"), "slot was not released"
EOF
wait_log "^127.0.0.1 holds 2 connections, closing its new ones" 2
wait_log "^127.0.0.1: 3 connections in [0-9]*s, held [0-9]*s in total, longest [0-9]*s, 1 refused$" 2
pass "--max-per-ip"

patched "$work/per-ip-once" "VISIT_MAX = 1"
start per-ip-once "$work/per-ip-once" --delay 1 --max-per-ip 2 --log-after 0
"$py" -I - "$port" <<'EOF' || fail "connection over --max-per-ip was not closed"
import socket, sys, time
addr = ("127.0.0.1", int(sys.argv[1]))
for pause in (1.3, 0):
    held = [socket.create_connection(addr, timeout=5) for _ in range(2)]
    assert all(s.recv(64).startswith(b"SSH-2.0-") for s in held)
    for _ in range(2):
        assert socket.create_connection(addr, timeout=5).recv(64) == b""
        time.sleep(pause)
    for s in held:
        s.close()
    time.sleep(0.3)
EOF
wait_log "^127.0.0.1: 0 connections, 2 still held, 1 refused$" 1
[ "$(grep -c "^127.0.0.1 holds 2 connections" "$work/per-ip-once.log")" = 2 ] || fail "per-IP message repeated while the address stayed at the limit"
pass "the --max-per-ip message repeats only after the address had no connections left"

NOFILE=64 start nofile ssh-kex-tarpit --delay 1
"$py" -I -c 'import socket, sys; assert socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5).recv(64)' "$port"
wait_log "^open file limit 64 leaves room for 47 clients, not --max-clients 4096$" 2
pass "--max-clients is capped by the open file limit"

start shutdown ssh-kex-tarpit --delay 1
knock 127.0.0.2 0
"$py" -I -c 'import socket, sys, time; s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5); s.recv(64); time.sleep(5)' "$port" &
pids+=($!)
wait_log "^listening on" 3
sleep 0.5
kill -TERM "$pid"
rc=0
wait "$pid" || rc=$?
[ "$rc" = 0 ] || fail "SIGTERM exit status $rc"
grep -q "^127.0.0.1: 1 connection, held [0-9]*s (shutdown)$" "$work/shutdown.log" || fail "held client not logged at shutdown"
grep -q "^127.0.0.2: 1 connection, held 0s$" "$work/shutdown.log" || fail "departed address not logged at shutdown"
pass "held clients and departed addresses are logged at shutdown"

read -r port port2 <<< "$(free_port 2)"
launch two "127.0.0.1:$port 127.0.0.1:$port2" ssh-kex-tarpit --delay 1
"$py" -I - "$port" "$port2" <<'EOF' || fail "second listening socket does not answer"
import socket, sys
for port in sys.argv[1:]:
    assert socket.create_connection(("127.0.0.1", int(port)), timeout=5).recv(64).startswith(b"SSH-2.0-")
EOF
wait_log "^listening on 127.0.0.1 port $port, 127.0.0.1 port $port2$" 2
pass "several listening sockets"

if "$py" -I -c 'import socket; socket.socket(socket.AF_INET6).bind(("::1", 0))' 2> /dev/null; then
    port=$(free_port)
    launch ipv6 "[::]:$port" ssh-kex-tarpit --delay 60 --log-after 0
    "$py" -I - "$port" <<'EOF' || fail "no answer over IPv6"
import socket, sys
for host in ("::1", "127.0.0.1"):
    s = socket.create_connection((host, int(sys.argv[1])), timeout=5)
    assert s.recv(64).startswith(b"SSH-2.0-")
    s.close()
EOF
    wait_log "^::1: 1 connection, held" 3
    wait_log "^127.0.0.1: 1 connection, held" 3
    pass "IPv6 and IPv4 on a dual-stack socket"
else
    skip "IPv6 (no ::1 here)"
fi

echo "all tests passed"
