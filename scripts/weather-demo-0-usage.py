#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Project only recorded usage for an explicitly selected root turn; no prompts."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

FIELDS = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens",
          "output_tokens", "reasoning_output_tokens")


def collect(paths, root_turn):
    if not re.fullmatch(r"[a-f0-9-]{36}", root_turn):
        raise ValueError("exact root turn UUID required")
    threads, seen = [], set()
    for path in paths:
        path = Path(path).resolve(strict=True)
        if path in seen:
            raise ValueError("duplicate session file")
        seen.add(path)
        if not path.is_file() or path.stat().st_size > 128 * 1024**2:
            raise ValueError("session file must be bounded")
        previous = dict.fromkeys(FIELDS, 0)
        totals = defaultdict(lambda: dict.fromkeys(FIELDS, 0))
        active, model, effort, thread, role = False, None, None, None, "principal"
        latest, events, selected = None, 0, False
        with path.open() as stream:
            for line in stream:
                entry = json.loads(line)
                value = entry.get("payload", {})
                kind = entry.get("type")
                if kind == "session_meta":
                    thread = value.get("id")
                    source = value.get("source")
                    if isinstance(source, dict):
                        role = source.get("subagent", {}).get("thread_spawn", {}).get("agent_role") or "subagent"
                elif kind == "turn_context":
                    model, effort = value.get("model"), value.get("effort")
                elif kind == "event_msg" and value.get("type") == "task_started":
                    active = value.get("root_turn_id") == root_turn
                    selected |= active
                elif kind == "event_msg" and value.get("type") == "task_complete":
                    active = False
                elif kind == "event_msg" and value.get("type") == "token_count" and value.get("info"):
                    usage = value["info"].get("total_token_usage")
                    if usage is None:
                        continue
                    current = {key: usage.get(key, 0) for key in FIELDS}
                    if not all(type(v) is int and v >= 0 for v in current.values()):
                        raise ValueError("invalid usage counter")
                    delta = {key: current[key] - previous[key] for key in FIELDS}
                    if any(v < 0 for v in delta.values()):
                        raise ValueError("counter reset: manual reconciliation required")
                    previous = current
                    if active:
                        if not isinstance(model, str) or not isinstance(effort, str):
                            raise ValueError("missing selected-turn model metadata")
                        target = totals[(model, effort)]
                        for key in FIELDS:
                            target[key] += delta[key]
                        events += any(delta.values())
                        latest = entry.get("timestamp")
        if selected:
            rows = []
            for (model, effort), values in sorted(totals.items()):
                if values["cached_input_tokens"] > values["input_tokens"]:
                    raise ValueError("cache counter exceeds input")
                rows.append(dict(model=model, effort=effort, **values,
                    uncached_input_tokens=values["input_tokens"] - values["cached_input_tokens"]))
            threads.append(dict(thread_id=thread, role=role, models=rows,
                nonzero_usage_events=events, latest_usage_timestamp=latest))
    if not threads:
        raise ValueError("selected root turn absent")
    return dict(schema=1, kind="weather-demo-recorded-model-usage", root_turn_id=root_turn,
        threads=threads, billing_estimate=False, snapshot_incomplete=True,
        notes=["Recorded cumulative-counter deltas only; duplicate snapshots add zero.",
               "Reasoning output is a subset of output and is not added again.",
               "Cache writes are reported separately; no subscription-cost inference.",
               "CI machine time and human review are not model tokens.",
               "Missing records, unlisted threads and later work are not measured."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-turn", required=True)
    parser.add_argument("sessions", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(collect(args.sessions, args.root_turn), sort_keys=True, indent=2))
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Usage projection rejected; no session content exported.\n")


if __name__ == "__main__":
    main()
