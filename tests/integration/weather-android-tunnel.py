#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Bounded API-only doorway from the Android sandbox to a disposable core VM.

The host owns the SSH identity outside the socket-only directory exposed to the
Android sandbox. The guest connects as the weather worker, never as root. This
transports original HTTP responses; it supplies neither weather data nor core
acceptance evidence. The joined runner must still verify custody and captures.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import runpy
import selectors
import select
import signal
import socket
import stat
import subprocess
import sys
import time

ROUTES = ("/api/volparossa/forecast", "/api/volparossa/air-quality")
ORIGIN = "http://127.0.0.1:43210"
MAX_REQUEST = 4096
MAX_RESPONSE = 256 * 1024 + 8192
EXCHANGE_SECONDS = 190
MAX_REQUESTS = 6
GUEST_STATE = Path("/run/volparossa-weather-android/endpoint.json")
GUEST_HELPER = "/usr/local/libexec/volparossa-weather-android-tunnel.py"


class TunnelInterrupted(Exception):
    """Do not let selectors interpret cancellation as a retryable EINTR."""


def require(value):
    if not value:
        raise ValueError("weather_android_tunnel_rejected")


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and str(path) == os.fspath(path.resolve(strict=True)))
    require(not path.is_symlink())
    return path


def owned(path, kind, mode, uid=None):
    path = canonical(path)
    info = path.lstat()
    require(kind(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
            and info.st_uid == (os.geteuid() if uid is None else uid))
    return info


def request_path(raw):
    """Admit one bodyless fixed GET; never forward caller headers or credentials."""
    require(type(raw) is bytes and len(raw) <= MAX_REQUEST and raw.endswith(b"\r\n\r\n"))
    lines = raw.decode("ascii").split("\r\n")
    require(len(lines) >= 4 and lines[-2:] == ["", ""])
    parts = lines[0].split(" ")
    require(len(parts) == 3 and parts[0] == "GET" and parts[1] in ROUTES and parts[2] == "HTTP/1.1")
    headers = {}
    for line in lines[1:-2]:
        require(":" in line and not line.startswith((" ", "\t")))
        name, value = line.split(":", 1)
        require(name and name == name.strip() and name.isascii())
        name = name.lower()
        require(name not in headers and all(c.isalnum() or c == "-" for c in name))
        require(all(32 <= ord(c) < 127 or c == "\t" for c in value))
        headers[name] = value.strip()
    require(headers.get("host") == "127.0.0.1:43210"
            and headers.get("origin") == ORIGIN
            and not set(headers) & {"authorization", "cookie", "proxy-authorization", "transfer-encoding", "expect"})
    require("content-length" not in headers or headers["content-length"] == "0")
    return parts[1]


def canonical_request(path):
    require(path in ROUTES)
    return (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n"
            f"Origin: {ORIGIN}\r\nConnection: close\r\n\r\n").encode("ascii")


def ssh_command(key, hosts):
    for path in (key, hosts):
        owned(path, stat.S_ISREG, 0o600)
    return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-p", "22223", "-i", str(key),
            "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + str(hosts),
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ClearAllForwardings=yes",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "vpci@127.0.0.1", "/usr/bin/sudo", "-n", "/usr/bin/python3", "-B", GUEST_HELPER, "guest"]


def group_alive(group):
    # Only process-group membership/state is read. No argv, environment or
    # unrelated process metadata is retained. Zombies cannot hold descriptors.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
            if int(fields[2]) == group and fields[0] not in ("Z", "X"):
                return True
        except FileNotFoundError:
            continue
    return False


def stop_child(child):
    # A reaped leader does not establish that its stdout-holding descendants
    # have stopped. The session/group was created and is owned by this exchange.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if group_alive(child.pid):
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
        until = time.monotonic() + 2
        while group_alive(child.pid) and time.monotonic() < until:
            time.sleep(0.02)
    child.wait(timeout=2)
    require(not group_alive(child.pid))


def exchange(command, request, deadline, *, client=None):
    """Own one SSH process group; bound output before collecting it."""
    require(request == canonical_request(request_path(request)))
    require(deadline > time.monotonic())
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    try:
        child.stdin.write(request)
        child.stdin.close()
        child.stdin = None
        response = bytearray()
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ, "upstream")
            if client is not None:
                ready.register(client, selectors.EVENT_READ, "client")
            while True:
                remaining = deadline - time.monotonic()
                events = ready.select(max(0, remaining))
                if remaining <= 0 or not events:
                    raise TimeoutError("weather_android_tunnel_deadline")
                if any(key.data == "client" for key, _ in events):
                    # A bodyless, single-request caller has no further bytes to
                    # send. EOF is cancellation; extra bytes are a protocol error.
                    if not client.recv(1, socket.MSG_PEEK):
                        raise BrokenPipeError("weather_android_tunnel_cancelled")
                    raise ValueError("weather_android_tunnel_extra_request_data")
                chunk = os.read(child.stdout.fileno(), min(65536, MAX_RESPONSE + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                require(len(response) <= MAX_RESPONSE)
        require(child.wait(timeout=max(0.001, deadline - time.monotonic())) == 0)
        if time.monotonic() >= deadline:
            raise TimeoutError("weather_android_tunnel_deadline")
        require(response.startswith(b"HTTP/1.1 ") and b"\r\n\r\n" in response)
        return bytes(response)
    finally:
        try:
            stop_child(child)
        finally:
            if child.stdin is not None:
                child.stdin.close()
            child.stdout.close()


def receive_request(connection, deadline):
    request = bytearray()
    while not request.endswith(b"\r\n\r\n"):
        connection.settimeout(max(0.001, min(3, deadline - time.monotonic())))
        chunk = connection.recv(min(1024, MAX_REQUEST + 1 - len(request)))
        require(chunk)
        request.extend(chunk)
        require(time.monotonic() < deadline and len(request) <= MAX_REQUEST)
    return canonical_request(request_path(bytes(request)))


def same_socket(path, identity):
    try:
        current = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISSOCK(current.st_mode) and current.st_uid == os.geteuid()
            and (current.st_dev, current.st_ino) == identity)


def serve(path, command, lifetime=480, *, notify=None, hold_open=False, observe_responses=False):
    require(type(lifetime) is int and 1 <= lifetime <= 480)
    require(type(hold_open) is bool)
    require(type(observe_responses) is bool)
    # Only the host observes response hashes. The installed, fixed-name guest
    # helper stays standalone and needs no extra root-staged Python modules.
    observe = runpy.run_path(str(Path(__file__).with_name("weather-android-evidence.py")))["response_observation"] \
        if observe_responses else None
    path = Path(path)
    parent_info = owned(path.parent, stat.S_ISDIR, 0o700)
    require(path.is_absolute() and path.name == "core-api.sock" and len(os.fsencode(path)) < 104)
    require(not path.exists() and not path.is_symlink())
    require(not list(path.parent.iterdir()))
    deadline = time.monotonic() + lifetime
    counts = {route: 0 for route in ROUTES}
    identity = None
    result = dict(schema=1, kind="weather-android-api-tunnel", completed=0, requests=counts,
                  original_response_bytes=True, joined_core_acceptance=False, cleanup_confirmed=False)
    if observe_responses:
        result.update(schema=6, responses=[])
    previous_umask = os.umask(0o077)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))  # Exclusive bind; never unlink a pre-existing name.
        info = path.lstat()
        identity = (info.st_dev, info.st_ino)
        os.chmod(path, 0o600)
        owned(path, stat.S_ISSOCK, 0o600)
        server.listen(1)
        if notify:
            notify()
        while result["completed"] < MAX_REQUESTS:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("weather_android_tunnel_lifetime")
            server.settimeout(remaining)
            connection, _ = server.accept()
            with connection:
                request = receive_request(connection, min(deadline, time.monotonic() + 3))
                route = request_path(request)
                require(counts[route] < 3)
                counts[route] += 1
                response = exchange(command, request, min(deadline, time.monotonic() + EXCHANGE_SECONDS),
                                    client=connection)
                observation = observe(route, counts[route], response) if observe is not None else None
                connection.settimeout(max(0.001, min(5, deadline - time.monotonic())))
                connection.sendall(response)
                if time.monotonic() >= deadline:
                    raise TimeoutError("weather_android_tunnel_deadline")
                result["completed"] += 1
                if observe_responses:
                    result["responses"].append(observation)
        require(set(counts.values()) == {3})
        if hold_open:
            # Keep the same inode available for the Android runner's final
            # identity check. The owner sends TERM only after joining that run.
            server.settimeout(max(0.001, deadline - time.monotonic()))
            unexpected, _ = server.accept()
            unexpected.close()
            raise ValueError("weather_android_tunnel_extra_request")
        return result
    except TunnelInterrupted:
        if hold_open and result["completed"] == MAX_REQUESTS:
            return result
        raise
    finally:
        server.close()
        os.umask(previous_umask)
        try:
            current_parent = owned(path.parent, stat.S_ISDIR, 0o700)
            parent_unchanged = ((current_parent.st_dev, current_parent.st_ino)
                                == (parent_info.st_dev, parent_info.st_ino))
        except (OSError, ValueError):
            parent_unchanged = False
        if identity is not None and parent_unchanged and same_socket(path, identity):
            path.unlink()
            result["cleanup_confirmed"] = True
        # A renamed/replaced path is not proof that our original name vanished.
        # Preserve the replacement and report uncertainty rather than delete it.


def read_until_eof(source, limit, deadline):
    data = bytearray()
    with selectors.DefaultSelector() as ready:
        ready.register(source, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not ready.select(remaining):
                raise TimeoutError("weather_android_tunnel_deadline")
            chunk = os.read(source.fileno(), min(1024, limit + 1 - len(data)))
            if not chunk:
                if time.monotonic() >= deadline:
                    raise TimeoutError("weather_android_tunnel_deadline")
                return bytes(data)
            data.extend(chunk)
            require(len(data) <= limit)


def forward_response(upstream, sink, deadline):
    """Stop upstream work when the SSH response reader disappears."""
    watch = select.poll()
    watch.register(upstream, select.POLLIN | select.POLLERR | select.POLLHUP)
    watch.register(sink, select.POLLERR | select.POLLHUP)
    total = 0
    descriptor = sink.fileno()
    blocking = os.get_blocking(descriptor)
    os.set_blocking(descriptor, False)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("weather_android_tunnel_deadline")
            events = watch.poll(max(1, min(1000, int(remaining * 1000))))
            if any(fd == descriptor for fd, _ in events):
                raise BrokenPipeError("weather_android_tunnel_cancelled")
            if not events:
                continue
            upstream.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = upstream.recv(min(65536, MAX_RESPONSE + 1 - total))
            if time.monotonic() >= deadline:
                raise TimeoutError("weather_android_tunnel_deadline")
            if not chunk:
                return
            total += len(chunk)
            require(total <= MAX_RESPONSE)
            pending = memoryview(chunk)
            with selectors.DefaultSelector() as writable:
                writable.register(descriptor, selectors.EVENT_WRITE)
                while pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not writable.select(remaining):
                        raise TimeoutError("weather_android_tunnel_deadline")
                    try:
                        count = os.write(descriptor, pending)
                    except BlockingIOError:
                        continue
                    require(count > 0)
                    pending = pending[count:]
    finally:
        os.set_blocking(descriptor, blocking)


def guest():
    require(sys.platform == "linux" and os.geteuid() == 0)
    owned(GUEST_STATE.parent, stat.S_ISDIR, 0o700, 0)
    info = owned(GUEST_STATE, stat.S_ISREG, 0o600, 0)
    require(info.st_size <= 2048 and info.st_nlink == 1)
    state = json.loads(GUEST_STATE.read_bytes())
    require(type(state) is dict and set(state) == {"schema", "socket", "control_gid", "expires_at"})
    require(type(state["schema"]) is int and state["schema"] == 1)
    group, expiry = state["control_gid"], state["expires_at"]
    require(type(group) is int and 1 <= group <= 65535
            and type(expiry) is int and 0 < expiry - time.time() <= 840)
    path = canonical(state["socket"])
    require(path.name == "core-api.sock" and len(os.fsencode(path)) < 104)
    owned(path.parent, stat.S_ISDIR, 0o700, 985)
    owned(path, stat.S_ISSOCK, 0o600, 985)
    # The fixed root-owned endpoint contains no arbitrary executable or account.
    # Drop all supplementary groups and both saved identities before any data IO.
    os.setgroups([])
    os.setresgid(group, group, group)
    os.setresuid(985, 985, 985)
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(38, 1, 0, 0, 0) == 0)  # PR_SET_NO_NEW_PRIVS
    require(os.getresuid() == (985, 985, 985) and os.getgroups() == [])
    deadline = min(time.monotonic() + EXCHANGE_SECONDS, time.monotonic() + expiry - time.time())
    request = read_until_eof(sys.stdin.buffer, MAX_REQUEST, min(deadline, time.monotonic() + 3))
    require(request == canonical_request(request_path(request)))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
        upstream.settimeout(max(0.001, deadline - time.monotonic()))
        upstream.connect(str(path))
        upstream.sendall(request)
        forward_response(upstream, sys.stdout.buffer, deadline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    commands.add_parser("guest")
    host = commands.add_parser("host")
    host.add_argument("--socket", required=True, type=Path)
    host.add_argument("--ssh-key", required=True, type=Path)
    host.add_argument("--known-hosts", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "guest":
        guest()
        return
    require(os.geteuid() != 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_REPOSITORY") == "VOLPAROSSA/volparossa"
            and os.environ.get("GITHUB_WORKFLOW") == "Weather Android protected core delivery")
    # Android sees only the socket parent; neither credentials nor other files.
    require(args.socket.parent.resolve() not in (args.ssh_key.parent.resolve(), args.known_hosts.parent.resolve()))
    result = serve(args.socket, ssh_command(args.ssh_key, args.known_hosts), hold_open=True, observe_responses=True)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    def interrupted(_number, _frame):
        raise TunnelInterrupted("weather_android_tunnel_interrupted")
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        main()
    except (OSError, ValueError, TunnelInterrupted, subprocess.SubprocessError):
        print("weather_android_tunnel_failed", file=sys.stderr)
        raise SystemExit(1) from None
