#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Project only recorded usage for explicitly selected root turns; no prompts."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

FIELDS = ("input_tokens", "cached_input_tokens", "cache_write_input_tokens",
          "output_tokens", "reasoning_output_tokens")


def collect(paths, root_turn):
    """Existing single-turn API, including rejection of repeated session files."""
    result = _collect(paths, [root_turn], deduplicate=False)
    result.pop("root_turn_ids")
    return result


def collect_many(paths, root_turn_ids):
    """Union selected turns; repeated UUIDs and file aliases contribute only once."""
    if isinstance(root_turn_ids, str):
        root_turn_ids = [root_turn_ids]
    return _collect(paths, root_turn_ids, deduplicate=True)


def _collect(paths, root_turn_ids, *, deduplicate):
    root_turn_ids = list(root_turn_ids)
    if not root_turn_ids or not all(isinstance(value, str) and re.fullmatch(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", value)
            for value in root_turn_ids):
        raise ValueError("exact root turn UUID required")
    root_turn_ids = sorted(set(root_turn_ids))
    wanted = set(root_turn_ids)
    threads, seen, selected_threads, observed = [], set(), set(), set()
    for path in paths:
        path = Path(path).resolve(strict=True)
        info = path.stat()
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            if deduplicate:
                continue
            raise ValueError("duplicate session file")
        seen.add(identity)
        if not path.is_file() or info.st_size > 128 * 1024**2:
            raise ValueError("session file must be bounded")
        previous = dict.fromkeys(FIELDS, 0)
        previous_missing = set(FIELDS)
        missing_counter_fields, selected_snapshots = set(), 0
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
                    root_turn = value.get("root_turn_id")
                    active = root_turn in wanted
                    selected |= active
                    if active:
                        observed.add(root_turn)
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
                    current_missing = set(FIELDS).difference(usage)
                    missing_for_delta = previous_missing | current_missing
                    previous, previous_missing = current, current_missing
                    if active:
                        selected_snapshots += 1
                        missing_counter_fields.update(missing_for_delta)
                        if not isinstance(model, str) or not isinstance(effort, str):
                            raise ValueError("missing selected-turn model metadata")
                        target = totals[(model, effort)]
                        for key in FIELDS:
                            target[key] += delta[key]
                        events += any(delta.values())
                        latest = entry.get("timestamp")
        if selected:
            if thread in selected_threads:
                raise ValueError("duplicate thread across distinct session files: manual reconciliation required")
            selected_threads.add(thread)
            rows = []
            for (model, effort), values in sorted(totals.items()):
                if values["cached_input_tokens"] > values["input_tokens"]:
                    raise ValueError("cache counter exceeds input")
                rows.append(dict(model=model, effort=effort, **values,
                    uncached_input_tokens=values["input_tokens"] - values["cached_input_tokens"]))
            availability = {key: ("no_selected_snapshot" if not selected_snapshots else
                "legacy_zero_default_used" if key in missing_counter_fields else
                "observed_in_delta_snapshots") for key in FIELDS}
            threads.append(dict(thread_id=thread, role=role, models=rows,
                missing_counter_fields=sorted(missing_counter_fields), counter_availability=availability,
                nonzero_usage_events=events, latest_usage_timestamp=latest))
    if not threads or observed != wanted:
        raise ValueError("selected root turn absent")
    result = dict(schema=1, kind="weather-demo-recorded-model-usage", root_turn_ids=root_turn_ids,
        threads=threads, billing_estimate=False, snapshot_incomplete=True,
        notes=["Recorded cumulative-counter deltas only; duplicate snapshots add zero.",
               "Reasoning output is a subset of output and is not added again.",
               "Cache writes are reported separately; no subscription-cost inference.",
               "CI machine time and human review are not model tokens.",
               "Missing counter fields in a selected delta or its baseline use legacy zero defaults; these zeros and derived uncached input are not confirmed measurements.",
               "Selected-window deltas can include unselected work when no intermediate counter snapshot separates the work.",
               "This projection is not exact task consumption or billed consumption; missing records can cause overcount as well as undercount.",
               "Unlisted threads and later work are outside this incomplete snapshot."])
    if len(root_turn_ids) == 1:
        result["root_turn_id"] = root_turn_ids[0]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-turn", required=True, action="append",
        help="selected root turn UUID; repeat to measure a union across resumed turns")
    parser.add_argument("sessions", nargs="+", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(collect_many(args.sessions, args.root_turn), sort_keys=True, indent=2))
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, "Usage projection rejected; no session content exported.\n")


if __name__ == "__main__":
    main()
