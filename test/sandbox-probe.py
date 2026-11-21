# Prints what a hijacked process could reach inside the sandbox. Run via sandbox-probe.sh.
import ctypes
import os
import socket
import stat
import subprocess

SKIP = ("/proc", "/sys", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
libc = ctypes.CDLL(None, use_errno=True)


def check(label, fn):
    try:
        out = fn()
    except Exception as e:
        print(f"blocked  {label}: {getattr(e, 'strerror', None) or e}")
    else:
        print(f"ALLOWED  {label}" + (f": {out}" if out else ""))


def walk():
    for d, dirs, files in os.walk("/", onerror=lambda e: None):
        dirs[:] = [x for x in dirs if os.path.join(d, x) not in SKIP]
        yield d, [os.path.join(d, f) for f in files]


def syscall(rc):
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def connect_unix(path):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        with socket.socket(socket.AF_UNIX, kind) as s:
            try:
                s.connect(path)
                return True
            except OSError:
                pass
    return False


def can_write(d):
    try:
        f = os.path.join(d, f".probe-{os.getpid()}")
        open(f, "x").close()
        os.unlink(f)
        return True
    except OSError:
        return False


print(f"uid {os.getuid()}, walking / without {', '.join(SKIP)}")
for fam in ("AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET"):
    check(f"socket({fam})", lambda f=fam: socket.socket(getattr(socket, f), socket.SOCK_DGRAM).close())
check("socketpair(AF_UNIX), needed by asyncio", lambda: [s.close() for s in socket.socketpair()] and None)

sockets, readable, writable = [], [], []
for d, files in walk():
    if can_write(d):
        writable.append(d)
    for f in files:
        try:
            mode = os.lstat(f).st_mode
        except OSError:
            continue
        if stat.S_ISSOCK(mode):
            if connect_unix(f):
                sockets.append(f)
        elif stat.S_ISREG(mode) and os.access(f, os.R_OK):
            readable.append(f)
print(f"connectable unix sockets: {sockets or 'none'}")
print(f"readable files: {len(readable)} {readable[:10]}")
print(f"writable dirs: {writable or 'none'}")

check("unshare(CLONE_NEWUSER)", lambda: syscall(libc.unshare(0x10000000)))
check("mount tmpfs", lambda: syscall(libc.mount(b"x", b"/tmp", b"tmpfs", 0, None)))
check("setuid(0)", lambda: os.setuid(0))
check("ptrace(ATTACH, 1)", lambda: syscall(libc.ptrace(16, 1, None, None)))
check("visible pids", lambda: " ".join(p for p in os.listdir("/proc") if p.isdigit()))
check("exec /bin/sh -c id", lambda: subprocess.run(["/bin/sh", "-c", "id"], capture_output=True, text=True).stdout.strip())
