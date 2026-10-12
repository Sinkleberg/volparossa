#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Separate late-provider availability proof; never a concurrency/speed substitute."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import select
import signal
import socket
import stat
import subprocess
import sys
import time

BASE = runpy.run_path(str(Path(__file__).with_name("content-provider-https-smoke.py")))
require, read, ROLES = BASE["require"], BASE["read"], BASE["ROLES"]
PREFIX = "content-provider-late-recovery"
NODES = ("relay4", "relay5")
TABLE = "vpa_content_late_gate"
LIMIT = 262144
GATE_NS = 6_000_000_000
BYTES = 2097275
SHA = hashlib.sha256(b"".join(bytes([16+i])*262144 for i in range(8)) + bytes([25])*123).hexdigest()
EVENTS = ("CONTENT_DISCOVERY_COMPLETED", "CONTENT_DISCOVERY_RECEIVED_OFFERS", "CONTENT_DISCOVERY_RECEIVED_EMPTY",
    "CONTENT_PROVIDER_QUERY_STARTED", "CONTENT_PROVIDER_OFFER_VERIFIED")
FAILURE_STAGES = ("gate-install", "gate-inspect", "fetch-start", "first-snapshot", "activate-b",
    "gate-release", "fetch-wait", "final-snapshot", "output")
FAILURE_CATEGORIES = ("command-failed", "timeout", "interrupted", "os-error", "invalid-evidence")


class FixtureCommandError(ValueError):
    def __init__(self, returncode):
        super().__init__("bounded fixture command failed")
        self.returncode = returncode


def failure_evidence(stage, error):
    category, code = "invalid-evidence", None
    if isinstance(error, FixtureCommandError): category, code = "command-failed", error.returncode
    elif isinstance(error, subprocess.TimeoutExpired): category = "timeout"
    elif isinstance(error, InterruptedError): category = "interrupted"
    elif isinstance(error, OSError): category = "os-error"
    value = dict(schema_version=1, kind="content-provider-late-recovery-failure", success=False,
        stage=stage, category=category, command_exit_code=code)
    validate_failure(value)
    return value


def validate_failure(value):
    require(set(value) == {"schema_version", "kind", "success", "stage", "category", "command_exit_code"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == "content-provider-late-recovery-failure" and value["success"] is False
        and value["stage"] in FAILURE_STAGES and value["category"] in FAILURE_CATEGORIES,
        "invalid fixture failure diagnostic")
    code = value["command_exit_code"]
    require((value["category"] == "command-failed" and type(code) is int and -255 <= code <= 255 and code != 0)
        or (value["category"] != "command-failed" and code is None), "invalid command failure status")


def path(work, suffix, extension="json"):
    return work / f"{PREFIX}-{suffix}.{extension}"


def write(target, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    require(len(raw) <= LIMIT, "evidence too large")
    with target.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(raw)


def private_read(target):
    require(target.resolve() == target and not target.is_symlink(), "unsafe private record")
    info = target.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= LIMIT, "wrong private record owner")
    return read(target)


def guest(work):
    require(os.geteuid() == 0 and socket.gethostname() == "volparossa-alpha"
        and work.is_absolute() and work.resolve() == work and work.parent == Path("/opt")
        and work.name.startswith("va.") and work.is_dir() and work.stat().st_uid == 0, "disposable guest required")
    result = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, timeout=3, check=False)
    require(result.returncode == 0 and result.stdout.strip() == b"kvm", "KVM guest required")


def namespace(work, expected=None):
    record = private_read(work / "helper-record-relay4.json")
    name = record["network_namespace"]
    require(record["node"] == "relay4" and record["unit"] == "volparossa-alpha-helper@relay4.service"
        and re.fullmatch(r"va-[0-9a-f]{8}-r4", name), "wrong provider namespace")
    info = os.stat(f"/run/netns/{name}")
    identity = f"{info.st_dev}:{info.st_ino}"
    require(identity == record["network_namespace_identity"]
        and (expected is None or expected == dict(name=name, identity=identity)), "namespace replaced")
    return dict(name=name, identity=identity)


def command(args, deadline, input_data=None):
    remaining = (deadline-time.monotonic_ns()) / 1e9
    require(remaining > 0, "fixture deadline exceeded")
    result = subprocess.run(args, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=min(remaining, 2), check=False)
    if result.returncode != 0: raise FixtureCommandError(result.returncode)
    require(len(result.stdout) <= LIMIT, "bounded fixture command output too large")
    return result.stdout


def gate_rules():
    return (f"table inet {TABLE} {{ chain input {{ type filter hook input priority -30; policy accept; "
        'iifname "r4x" ip saddr 46.162.3.1 ip daddr 49.165.5.1 tcp dport 18080 counter drop; }\n}\n').encode()


def validate_gate(value):
    entries = value["nftables"]
    require(len(entries) == 4, "unexpected gate objects")
    table = [item["table"] for item in entries if "table" in item]
    chains = [item["chain"] for item in entries if "chain" in item]
    rules = [item["rule"] for item in entries if "rule" in item]
    require(len(table) == len(chains) == len(rules) == 1
        and table[0]["family"] == "inet" and table[0]["name"] == TABLE
        and chains[0]["family"] == "inet" and chains[0]["table"] == TABLE and chains[0]["name"] == "input"
        and chains[0]["type"] == "filter" and chains[0]["hook"] == "input"
        and chains[0]["prio"] == -30 and chains[0]["policy"] == "accept"
        and rules[0]["family"] == "inet" and rules[0]["table"] == TABLE and rules[0]["chain"] == "input",
        "gate escaped exact input table")
    expressions = rules[0]["expr"]
    expected = [dict(match=dict(op="==", left=dict(meta=dict(key="iifname")), right="r4x")),
        *[dict(match=dict(op="==", left=dict(payload=dict(protocol="ip", field=field)), right=address))
            for field, address in (("saddr", "46.162.3.1"), ("daddr", "49.165.5.1"))],
        dict(match=dict(op="==", left=dict(payload=dict(protocol="tcp", field="dport")), right=18080))]
    require(len(expressions) == 6 and expressions[:4] == expected and expressions[5] == {"drop": None}
        and set(expressions[4]) == {"counter"}
        and set(expressions[4]["counter"]) == {"packets", "bytes"}
        and all(type(value) is int and value >= 0 for value in expressions[4]["counter"].values()), "wrong gate rule")


def remove_gate(work, guest_checked=False):
    record = path(work, "gate", "state")
    if not record.exists() and not record.is_symlink(): return
    if not guest_checked: guest(work)
    state = private_read(record); ns = namespace(work, state["namespace"])
    base = ["ip", "netns", "exec", ns["name"], "nft"]
    # Listing all table names lets absence be distinguished from command failure.
    deadline = time.monotonic_ns() + 2_000_000_000
    tables = json.loads(command(base + ["-j", "list", "tables"], deadline))
    present = any(row.get("table", {}).get("family") == "inet" and row.get("table", {}).get("name") == TABLE
        for row in tables["nftables"])
    if present:
        snapshot = json.loads(command(base + ["-j", "list", "table", "inet", TABLE], deadline))
        validate_gate(snapshot)
        command(base + ["delete", "table", "inet", TABLE], deadline)


def process_identity(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return dict(pid=pid, start_ticks=int(fields[19]))


def stop_fetch(work):
    record = path(work, "fetch", "state")
    if not record.exists() and not record.is_symlink(): return
    guest(work); identity = private_read(record)
    require(set(identity) == {"pid", "start_ticks"} and all(type(v) is int and v > 1 for v in identity.values()),
        "wrong fetch process record")
    try: descriptor = os.pidfd_open(identity["pid"])
    except ProcessLookupError: return
    try:
        require(process_identity(identity["pid"]) == identity, "fetch PID reused")
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        poll = select.poll(); poll.register(descriptor, select.POLLIN)
        if not poll.poll(1000):
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            require(poll.poll(1000), "owned fetch did not terminate")
    except ProcessLookupError: pass
    finally: os.close(descriptor)


def cleanup(work):
    # Gate release must not wait for child termination near the connect deadline.
    try: remove_gate(work)
    finally: stop_fetch(work)


def event_rows(raw, baseline):
    require(len(raw) <= LIMIT, "event snapshot too large")
    rows = []
    lines = raw.decode("ascii").splitlines()
    require(len(lines) <= 400, "event ring bound exceeded")
    stamps = []
    for line in lines:
        fields = line.split()
        if not fields or not fields[0].isdigit(): continue
        timestamp = int(fields[0]); stamps.append(timestamp)
        if timestamp <= baseline or len(fields) < 3 or not fields[2].startswith("event="): continue
        code = fields[2][6:]
        if code in EVENTS: rows.append(dict(unix_ms=timestamp, event=code))
    require(not (len(lines) == 400 and stamps and min(stamps) > baseline), "event ring lost interval")
    return rows


def count(rows, code): return sum(row["event"] == code for row in rows)


def first_snapshot(snapshot):
    return (count(snapshot["client"], EVENTS[0]) == count(snapshot["client"], EVENTS[1]) == 1
        and count(snapshot["client"], EVENTS[2]) == 0
        and count(snapshot["broker"], EVENTS[3]) == count(snapshot["broker"], EVENTS[4]) == 1)


def run(work, binary, provider_namespace):
    guest(work); ns = namespace(work)
    require(ns["name"] == provider_namespace and binary.resolve() == binary and binary.is_file(), "wrong executable/namespace")
    layout, peers, publication = (read(path(work, name)) for name in ("layout", "peers", "publication"))
    control = [node for node in ("relay0", "relay1", "relay2") if peers[node] == layout["control_relay_peer_id"]]
    require(len(control) == 1 and layout["provider_nodes"] == list(NODES), "wrong control/provider layout")
    native = work / "state-client/content-late-recovery"
    require(all(not (native / name).exists() and not (native / name).is_symlink()
        for name in ("cache", "object.bin")), "not cold")
    def cli(node, *args): return [str(binary), "--control-socket", str(work / f"runtime-{node}/control/agent.sock"), *args]
    def snapshot(baseline, deadline):
        return {label: event_rows(command(cli(node, "logs", "--limit", "400"), deadline), baseline)
            for label, node in (("client", "client"), ("broker", control[0]))}
    baseline = time.time_ns() // 1000000
    time.sleep(0.002)  # Only cross the event clock tick, never wait for provider readiness.
    tables = json.loads(command(["ip", "netns", "exec", ns["name"], "nft", "-j", "list", "tables"],
        time.monotonic_ns()+2_000_000_000))
    require(not any(row.get("table", {}).get("family") == "inet" and row.get("table", {}).get("name") == TABLE
        for row in tables["nftables"]), "gate table collision")
    gate_start = time.monotonic_ns(); deadline = gate_start + GATE_NS
    write(path(work, "gate", "state"), dict(namespace=ns))
    process, success = None, False
    stage = "gate-install"
    def interrupted(_signal, _frame): raise InterruptedError("fixture interrupted")
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        command(["ip", "netns", "exec", ns["name"], "nft", "-f", "-"], deadline, gate_rules())
        stage = "gate-inspect"
        installed = json.loads(command(["ip", "netns", "exec", ns["name"], "nft", "-j", "list", "table", "inet", TABLE], deadline))
        validate_gate(installed); write(path(work, "gate-installed"), installed)
        stage = "fetch-start"
        started = time.monotonic_ns()
        with path(work, "fetch").open("xb") as stdout, path(work, "fetch", "err").open("xb") as stderr:
            os.fchmod(stdout.fileno(), 0o600); os.fchmod(stderr.fileno(), 0o600)
            process = subprocess.Popen(cli("client", "content", "fetch", "--manifest", str(native / "manifest.bin"),
                "--publisher-key", publication["publisher_hex"], "--cache", str(native / "cache"),
                "--output", str(native / "object.bin")), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            write(path(work, "fetch", "state"), process_identity(process.pid))
            stage = "first-snapshot"
            while True:
                require(process.poll() is None, "fetch ended before late activation")
                initial = snapshot(baseline, deadline)
                require(count(initial["client"], EVENTS[0]) <= 1, "first snapshot already passed")
                if first_snapshot(initial): break
                require(time.monotonic_ns() < deadline - 2_000_000_000, "first snapshot not available within gate budget")
                time.sleep(0.02)
            observed = time.monotonic_ns()
            write(path(work, "first-snapshot"), initial)
            stage = "activate-b"
            activated = time.monotonic_ns()
            serve = json.loads(command(cli("relay5", "content", "serve", "--manifest", str(native / "manifest.bin"),
                "--publisher-key", publication["publisher_hex"], "--cache", str(work / "state-relay5/content-late-recovery/cache"),
                "--bind", "50.166.6.1:18080", "--advertised-hostname", "provider-b.volparossa.test"), deadline))
            require(serve["serving"] is True and serve["publications"] == 1 and serve["replication_enabled"] is False,
                "late service did not acknowledge registration")
            acknowledged = time.monotonic_ns(); write(path(work, "relay5-serve"), serve)
            stage = "gate-release"
            command(["ip", "netns", "exec", ns["name"], "nft", "delete", "table", "inet", TABLE], deadline)
            released = time.monotonic_ns(); require(released <= deadline, "gate exceeded six seconds")
            stage = "fetch-wait"
            status = process.wait(timeout=max(0.001, (started+300_000_000_000-time.monotonic_ns())/1e9))
            if status != 0: raise FixtureCommandError(status)
        completed = time.monotonic_ns()
        stage = "final-snapshot"
        final = snapshot(baseline, time.monotonic_ns()+5_000_000_000)
        write(path(work, "final-snapshot"), final)
        stage = "output"
        output = native / "object.bin"
        require(output.is_file() and not output.is_symlink() and output.stat().st_size == BYTES, "wrong output")
        write(path(work, "object"), dict(bytes=output.stat().st_size, sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
            event_baseline_unix_ms=baseline, gate_started_ns=gate_start, fetch_started_ns=started,
            first_snapshot_observed_ns=observed, late_activation_started_ns=activated,
            late_activation_acknowledged_ns=acknowledged, gate_released_ns=released, fetch_completed_ns=completed,
            cold_cache=True, consumer_provider_hints=False, origin_fallback=False))
        success = True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Retain only fixed classifications before cleanup can raise a second error.
        # No arbitrary command, path, exception text or child stderr is exported.
        write(path(work, "failure"), failure_evidence(stage, error))
        raise
    finally:
        gate_removed = False
        try:
            # Already checked the guest before installation. Revalidate only the
            # exact root intent/namespace now: bounded release precedes reaping.
            remove_gate(work, guest_checked=True); gate_removed = True
        finally:
            try:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=2)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)
                write(path(work, "run-cleanup"), dict(fetch_reaped=process is None or process.poll() is not None,
                    gate_removed=gate_removed, operation_completed=success))
            finally:
                for sig, handler in handlers.items(): signal.signal(sig, handler)


def validate(value):
    require(value["success"] is True and value["schema_version"] == 1
        and value["concurrent_provider_overlap_claimed"] is False, "wrong late-recovery scope")
    publication, output, fetch = (value[k] for k in ("publication", "output", "fetch"))
    require(publication["report_kind"] == "volparossa-content-late-provider-seed"
        and publication["name"] == "disposable-late-native-publication"
        and publication["bytes"] == fetch["bytes"] == output["bytes"] == BYTES
        and publication["object_sha256"] == output["sha256"] == SHA
        and publication["chunks"] == fetch["chunks"] == 9
        and publication["replica_a_chunks"] == 5 and publication["replica_b_chunks"] == 4
        and publication["replica_a_bytes"] == 1048699 and publication["replica_b_bytes"] == 1048576
        and publication["publisher_removed"] is True and publication["publisher_private_key_persisted"] is False
        and publication["recipient_encrypted"] is False, "fresh complementary publication not proven")
    peers, layout = value["expected_peers"], value["layout"]
    control = [node for node in ("relay0", "relay1", "relay2") if peers[node] == layout["control_relay_peer_id"]]
    require(len(control) == 1 and layout["provider_nodes"] == list(NODES)
        and all(value[k]["control_relay_peer_id"] == layout["control_relay_peer_id"] for k in ("status_before", "status_after", "fetch"))
        and fetch["operation"] == "native_content" and fetch["providers_used"] == len(fetch["provider_peer_ids"]) == 2
        and set(fetch["provider_peer_ids"]) == {peers[node] for node in NODES}
        and fetch["peer_bytes"] == BYTES and fetch["origin_body_bytes"] == fetch["origin_range_requests"] == 0
        and fetch["origin_authenticated"] is False, "real independent protected suppliers not proven")
    before, live = value["selected_before"], value["selected_route"]
    require(before["route_context_id"] == live["route_context_id"] != value["previous_context"]
        and before["benchmark_slots"] == live["benchmark_slots"] and before["transport"] == "mptcp", "route changed or not fresh")
    BASE["validate_path"](value, peers, list(NODES), False)
    for node, size in zip(NODES, (1048699, 1048576)):
        require(size <= value["privacy"]["exit"]["provider_application"][node]["response_payload_bytes"] <= size+131072,
            "provider shard traffic inconsistent")
    validate_gate(value["gate"])
    require(first_snapshot(value["first_snapshot"]), "first generic snapshot was not one verified offer")
    final = value["final_snapshot"]
    require(2 <= count(final["client"], EVENTS[0]) <= 3 and count(final["client"], EVENTS[1]) >= 2
        and 2 <= count(final["broker"], EVENTS[3]) <= 3 and 3 <= count(final["broker"], EVENTS[4]) <= 48,
        "bounded genuine rediscovery not proven")
    for label in ("client", "broker"):
        require(final[label][:len(value["first_snapshot"][label])] == value["first_snapshot"][label], "snapshot lineage changed")
        require(all(row["event"] in EVENTS and type(row["unix_ms"]) is int
            and row["unix_ms"] > output["event_baseline_unix_ms"] for row in final[label]), "invalid event interval")
    times = [output[k] for k in ("gate_started_ns", "fetch_started_ns", "first_snapshot_observed_ns",
        "late_activation_started_ns", "late_activation_acknowledged_ns", "gate_released_ns", "fetch_completed_ns")]
    require(all(type(v) is int and v > 0 for v in times) and times == sorted(times)
        and times[5]-times[0] <= GATE_NS and 0 < times[-1]-times[1] <= 300_000_000_000
        and output["cold_cache"] is True and output["consumer_provider_hints"] is False and output["origin_fallback"] is False,
        "activation ordering or absolute gate/transfer bound violated")
    for node in NODES:
        records = value["providers"][node]
        require(records["before"]["serving"] is False and records["before"]["publications"] == 0
            and records["serve"]["serving"] is True and records["serve"]["publications"] == 1
            and records["serve"]["replication_enabled"] is False
            and records["stop"]["serving"] is False and records["stop"]["publications"] == 0, "provider lifecycle incomplete")
    require(value["run_cleanup"] == dict(fetch_reaped=True, gate_removed=True, operation_completed=True)
        and value["cleanup"] == dict(route_disconnected=True, active_contexts=0, paths_empty=True,
            client_output_removed=True, client_manifest_removed=True, client_mount_isolated=True), "cleanup/isolation incomplete")
    validate_control(value, control[0])


def validate_control(value, broker):
    capture, routes = value["control_underlay"]["capture"], value["control_underlay"]["routes"]
    pairs = {f"lc{i}": [BASE["PUBLIC_IPS"][broker], BASE["PUBLIC_IPS"][node]] for i, node in enumerate(NODES)}
    require(capture["capture_role"] == "content-control" and capture["content_provider_mode"] is True
        and capture["content_control_pairs"] == pairs and set(capture["interfaces"]) == set(pairs)
        and set(capture["content_control_packets"]) == set(pairs)
        and capture["unexpected_provider_control_packets"] == capture["unexpected_provider_application_packets"] == 0
        and all(value == 0 for counters in capture["provider_application"].values() for value in counters.values()),
        "unexpected control-link traffic")
    BASE["validate_drained"](capture)
    for i, node in enumerate(NODES):
        require(all(capture["content_control_packets"][f"lc{i}"][key] > 0 for key in ("inbound", "outbound")), "missing control traffic")
        for direction, dev, gateway, source, destination in (
                ("out", f"lc{i}", f"10.241.{86+i}.2", BASE["PUBLIC_IPS"][broker], BASE["PUBLIC_IPS"][node]),
                ("back", f"lp{i}", f"10.241.{86+i}.1", BASE["PUBLIC_IPS"][node], BASE["PUBLIC_IPS"][broker])):
            rows = routes[node][direction]
            require(len(rows) == 1 and all(rows[0].get(k) == v for k, v in
                dict(dev=dev, gateway=gateway, prefsrc=source, dst=destination).items()), "wrong dedicated control route")


def build_evidence(work):
    value = {key: read(path(work, suffix)) for key, suffix in (("publication", "publication"), ("layout", "layout"),
        ("status_before", "status-before"), ("status_after", "status-after"), ("fetch", "fetch"), ("output", "object"),
        ("selected_before", "selection"), ("selected_route", "live-selection"), ("cleanup", "cleanup"),
        ("first_snapshot", "first-snapshot"), ("final_snapshot", "final-snapshot"), ("gate", "gate-installed"), ("run_cleanup", "run-cleanup"))}
    value.update(schema_version=1, success=True, concurrent_provider_overlap_claimed=False,
        expected_peers=read(work / "a01-expected-peers.json"),
        previous_context=read(work / "content-provider-adaptive-selection.json")["route_context_id"],
        providers={node: {op: read(path(work, f"{node}-{op}")) for op in ("before", "serve", "stop")} for node in NODES},
        privacy={role: read(path(work, f"privacy-{role}")) for role in ROLES},
        control_underlay=dict(capture=read(path(work, "control-privacy")), routes={node: {direction:
            json.loads(path(work, f"control-{node}-{direction}").read_text()) for direction in ("out", "back")} for node in NODES}))
    status = path(work, "final-status", "txt").read_text().splitlines()
    require("connected: false" in status and "active contexts: 0" in status
        and path(work, "final-paths", "txt").read_text() == "", "route still active")
    validate(value); return value


def main():
    action, *args = sys.argv[1:]
    if action == "run" and len(args) == 3: run(Path(args[0]), Path(args[1]), args[2])
    elif action == "cleanup" and len(args) == 1: cleanup(Path(args[0]))
    elif action == "evidence" and len(args) == 2: write(Path(args[1]), build_evidence(Path(args[0])))
    else: raise ValueError("invalid late recovery action")


if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("late-provider fixture failed closed", file=sys.stderr); raise SystemExit(1)
