#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Inert KVM diagnostics tests. All device/identity syscalls are replaced."""
import copy
import errno
import json
import os
from pathlib import Path
import runpy
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
K = runpy.run_path(str(HERE / "weather-android-kvm.py"))
IDENTITY = dict(core_commit="a" * 40, weather_commit="f6ee829961da387d9c0cd71b7163b47baab434fa",
    run_id="123", run_attempt="1")


def private_fixture():
    return dict(credentials=[12345] * 3 + [23456] * 3, groups=[23456, 34567],
        device=[42, 77123, 2560, stat.S_IFCHR | 0o660, 0, 34567], state="character",
        open_result="opened", **dict.fromkeys(K["BOOLS"], True))


class Probe(unittest.TestCase):
    def observe(self, *, mode=stat.S_IFCHR | 0o660, uid=0, fail=None, access=True, changed=False):
        info = SimpleNamespace(st_dev=42, st_ino=77123, st_rdev=2560, st_mode=mode, st_uid=uid, st_gid=34567)
        current = SimpleNamespace(**vars(info))
        if changed: current.st_ino += 1
        with patch.object(os, "getresuid", return_value=(12345,) * 3), \
                patch.object(os, "getresgid", return_value=(23456,) * 3), \
                patch.object(os, "getgroups", return_value=[34567, 23456]), \
                patch.object(os, "lstat", side_effect=fail if fail and fail[0] == "stat" else None,
                    return_value=info) as lookup, \
                patch.object(os, "access", return_value=access) as check, \
                patch.object(os, "open", return_value=91) as opened, \
                patch.object(os, "fstat", return_value=current), patch.object(os, "close") as closed:
            if fail:
                (lookup if fail[0] == "stat" else opened).side_effect = fail[1]
            value = K["snapshot"]()
        K["validate_private"](value)
        return value, lookup, check, opened, closed

    def test_only_fixed_device_open_close_no_device_io_and_both_identity_access_modes(self):
        value, lookup, check, opened, closed = self.observe()
        self.assertEqual(value, private_fixture())
        self.assertTrue(K["usable"](value))
        lookup.assert_called_once_with("/dev/kvm")
        opened.assert_called_once_with("/dev/kvm", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        closed.assert_called_once_with(91)
        self.assertEqual([(call.args[1], call.kwargs) for call in check.call_args_list], [
            (os.R_OK, dict(effective_ids=False, follow_symlinks=False)),
            (os.W_OK, dict(effective_ids=False, follow_symlinks=False)),
            (os.R_OK, dict(effective_ids=True, follow_symlinks=False)),
            (os.W_OK, dict(effective_ids=True, follow_symlinks=False))])

    def test_missing_symlink_regular_and_nonroot_device_are_never_opened(self):
        for options, state in ((dict(fail=("stat", FileNotFoundError("PRIVATE"))), "missing"),
                (dict(fail=("stat", PermissionError("PRIVATE"))), "unavailable"),
                (dict(mode=stat.S_IFLNK | 0o777), "symlink"),
                (dict(mode=stat.S_IFREG | 0o600), "other"), (dict(uid=1001), "character")):
            value, _, checked, opened, closed = self.observe(**options)
            self.assertEqual(value["state"], state); self.assertFalse(K["usable"](value))
            checked.assert_not_called(); opened.assert_not_called(); closed.assert_not_called()
            self.assertNotIn("PRIVATE", json.dumps(value))

    def test_errors_have_finite_labels_and_no_raw_exception_or_numeric_ids_exported(self):
        for code, label in ((errno.EACCES, "eacces"), (errno.EPERM, "eperm"), (errno.ENOENT, "enoent"),
                (errno.ENODEV, "enodev"), (errno.EBUSY, "ebusy"), (errno.EIO, "other")):
            value, _, _, _, closed = self.observe(fail=("open", OSError(code, "PRIVATE_CANARY", "/private/path")))
            self.assertEqual(value["open_result"], label); self.assertFalse(K["usable"](value))
            closed.assert_not_called()
            raw = json.dumps(K["receipt"](IDENTITY, "owner", value))
            for forbidden in ("PRIVATE", "/private", "/dev", "12345", "23456", "34567", "77123"):
                self.assertNotIn(forbidden, raw)

    def test_access_denied_and_device_replacement_are_not_usable(self):
        value, _, _, opened, closed = self.observe(access=False)
        self.assertFalse(K["usable"](value)); opened.assert_called_once(); closed.assert_called_once()
        value, _, _, _, closed = self.observe(changed=True)
        self.assertEqual(value["open_result"], "device_changed")
        self.assertFalse(K["usable"](value)); closed.assert_called_once()

    def test_long_interval_comparisons_distinguish_identity_groups_mode_device_and_owner(self):
        baseline = private_fixture()
        for field, index, expected in (("credentials", 0, "same_identity"), ("groups", 0, "same_groups"),
                ("device", 1, "same_device"), ("device", 3, "same_mode"), ("device", 5, "same_device_owner")):
            value = copy.deepcopy(baseline); value[field][index] += 1
            projected = K["project"](value, baseline)
            self.assertFalse(projected[expected])
            self.assertTrue(all(projected[k] for k in K["COMPARISONS"] if k != expected))
        projected = K["project"](baseline)
        self.assertTrue(all(projected[k] is None for k in K["COMPARISONS"]))

    def test_private_baseline_is_closed_bounded_and_run_bound(self):
        original = K["baseline_record"](IDENTITY, private_fixture())
        self.assertEqual(K["baseline"](original, IDENTITY), private_fixture())
        for update in (dict(schema=True), dict(extra="PRIVATE"), dict(identity=dict(IDENTITY, run_attempt="2")),
                dict(snapshot=dict(private_fixture(), groups=list(range(257)))),
                dict(snapshot=dict(private_fixture(), credentials=[0] * 5)),
                dict(snapshot=dict(private_fixture(), device=[True] * 6)),
                dict(snapshot=dict(private_fixture(), groups=[2, 1]))):
            value = dict(original); value.update(update)
            with self.assertRaises(ValueError): K["baseline"](value, IDENTITY)

    def test_native_and_receipt_schemas_reject_raw_fields_unknown_states_and_acceptance(self):
        before = private_fixture()
        native = K["native_record"](IDENTITY, before, before, "available", before)
        receipt = K["receipt"](IDENTITY, "owner", before, "available", native)
        self.assertEqual(K["validate_receipt"](receipt), receipt)
        for update in (dict(schema=True), dict(joined_core_acceptance=True), dict(raw="PRIVATE"),
                dict(diagnostic_only=False), dict(before_main=dict(native["before_main"], real_read=1)),
                dict(before_main=dict(native["before_main"], open_result="PRIVATE")), dict(baseline_state="absent")):
            value = dict(native); value.update(update)
            with self.assertRaises(ValueError): K["validate_native"](value)
        for update in (dict(joined_core_acceptance=True), dict(physical_device=True), dict(production_authority=True),
                dict(diagnostic_only=False), dict(extra="PRIVATE"), dict(phase="PRIVATE"),
                dict(native=dict(state="absent", record=native)),
                dict(native=dict(state="available", record=dict(native, identity=dict(IDENTITY, run_attempt="2"))))):
            value = dict(receipt); value.update(update)
            with self.assertRaises(ValueError): K["validate_receipt"](value)


if __name__ == "__main__": unittest.main()
