#!/usr/bin/env python3
"""Synthetic, inert regression tests for storage-provider-usage-snapshot.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location("storage_provider_usage_snapshot", HERE / "storage-provider-usage-snapshot.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SNAPSHOT)

SCHEMA_SQL = """
CREATE TABLE storage_meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 version INTEGER NOT NULL, store_id BLOB NOT NULL CHECK(length(store_id) = 32),
 capacity_bytes INTEGER NOT NULL CHECK(capacity_bytes > 0),
 min_free_bytes INTEGER NOT NULL CHECK(min_free_bytes >= 0),
 admission_target_bytes INTEGER NOT NULL CHECK(admission_target_bytes >= 0 AND admission_target_bytes <= capacity_bytes)
) STRICT;
CREATE TABLE leases (
 lease_id BLOB PRIMARY KEY CHECK(length(lease_id) = 16),
 ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes >= 0),
 sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
 expires INTEGER NOT NULL CHECK(expires > 0),
 committed INTEGER NOT NULL CHECK(committed IN (0,1))
) STRICT;
CREATE TABLE chunks (
 lease_id BLOB NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
 sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
 payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 262144),
 PRIMARY KEY(lease_id, ordinal)
) STRICT;
"""


class Fixture:
    def __init__(self, parent: Path, capacity: int = 10_000):
        parent.mkdir(parents=True, exist_ok=True)
        self.path = parent / "store"
        self.path.mkdir(mode=0o700)
        store_id = bytes(range(32))
        d = self.path.stat()
        owner = (b"VPST0001" + store_id + d.st_dev.to_bytes(8, "little")
                 + d.st_ino.to_bytes(8, "little") + d.st_uid.to_bytes(4, "little"))
        (self.path / SNAPSHOT.OWNER_NAME).write_bytes(owner)
        os.chmod(self.path / SNAPSHOT.OWNER_NAME, 0o600)
        self.dbpath = self.path / SNAPSHOT.DB_NAME
        db = sqlite3.connect(self.dbpath)
        db.executescript(SCHEMA_SQL)
        db.execute(f"PRAGMA application_id={SNAPSHOT.APPLICATION_ID}")
        db.execute("PRAGMA user_version=2")
        db.execute("INSERT INTO storage_meta VALUES(1, 2, ?, ?, 0, ?)", (store_id, capacity, capacity))
        db.commit()
        db.close()
        os.chmod(self.dbpath, 0o600)

    def add_lease(self, number: int, size: int, committed: int, expires: int = 1) -> None:
        db = sqlite3.connect(self.dbpath)
        db.execute("INSERT INTO leases VALUES(?, ?, ?, ?, ?)",
                   (number.to_bytes(16, "little"), size, bytes(32), expires, committed))
        db.commit()
        db.close()


def inventory(path: Path) -> tuple[tuple[str, ...], tuple]:
    names = tuple(sorted(p.name for p in path.iterdir()))
    details = []
    for name in names:
        p = path / name
        st = p.stat(follow_symlinks=False)
        details.append((name, st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode),
                        st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                        hashlib.sha256(p.read_bytes()).hexdigest() if stat.S_ISREG(st.st_mode) else None))
    return names, tuple(details)


class UsageSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="storage-usage-snapshot-", dir=ROOT)
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def observed(self, fixture: Fixture, reserved: int, committed: int, leases: int) -> None:
        before = inventory(fixture.path)
        result = SNAPSHOT.observe(str(fixture.path))
        after = inventory(fixture.path)
        self.assertEqual(result, {"version": 1, "state": "observed", "reason": None,
                                  "reserved_bytes": reserved, "committed_bytes": committed,
                                  "leases": leases, "owner_cleanup_proven": False})
        self.assertEqual(before, after)

    def unavailable(self, path: Path, reason: str) -> None:
        result = SNAPSHOT.observe(str(path))
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["reason"], reason)
        self.assertIsNone(result["reserved_bytes"])
        self.assertIsNone(result["committed_bytes"])
        self.assertIsNone(result["leases"])
        self.assertFalse(result["owner_cleanup_proven"])

    def test_zero_usage_is_observed_and_nonmutating(self) -> None:
        fixture = Fixture(self.root)
        self.observed(fixture, 0, 0, 0)

    def test_reserved_committed_and_expired_undeleted_leases_are_counted(self) -> None:
        fixture = Fixture(self.root)
        fixture.add_lease(1, 37, 0, expires=1)
        fixture.add_lease(2, 63, 1, expires=1)
        self.observed(fixture, 37, 63, 2)

    def test_busy_owner_lock_is_unavailable(self) -> None:
        fixture = Fixture(self.root)
        fd = os.open(fixture.path / SNAPSHOT.OWNER_NAME, os.O_RDONLY)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.unavailable(fixture.path, "busy")
        finally:
            os.close(fd)

    def test_missing_store_and_bad_owner_identity_fail_closed(self) -> None:
        self.unavailable(self.root / "missing", "owner")
        fixture = Fixture(self.root)
        owner = fixture.path / SNAPSHOT.OWNER_NAME
        data = bytearray(owner.read_bytes())
        data[40] ^= 1
        owner.write_bytes(data)
        self.unavailable(fixture.path, "owner")

    def test_owner_fifo_returns_bounded_unavailable_without_hanging(self) -> None:
        fixture = Fixture(self.root)
        owner = fixture.path / SNAPSHOT.OWNER_NAME
        owner.unlink()
        os.mkfifo(owner, 0o600)
        completed = subprocess.run(
            [sys.executable, str(HERE / "storage-provider-usage-snapshot.py"), str(fixture.path)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        output = json.loads(completed.stdout)
        self.assertEqual(output["state"], "unavailable")
        self.assertEqual(output["reason"], "owner")
        self.assertIsNone(output["reserved_bytes"])
        self.assertIsNone(output["committed_bytes"])
        self.assertIsNone(output["leases"])
        self.assertNotIn(str(fixture.path), completed.stdout)
        self.assertNotIn("private", completed.stderr.lower())

    def test_owner_mode_symlink_hardlink_and_database_file_safety(self) -> None:
        fixture = Fixture(self.root)
        owner = fixture.path / SNAPSHOT.OWNER_NAME
        os.chmod(owner, 0o640)
        self.unavailable(fixture.path, "owner")
        os.chmod(owner, 0o600)
        outside = self.root / "outside"
        outside.write_bytes(owner.read_bytes())
        owner.unlink()
        owner.symlink_to(outside)
        self.unavailable(fixture.path, "owner")
        owner.unlink()
        owner.write_bytes(outside.read_bytes())
        os.chmod(owner, 0o600)
        os.link(owner, self.root / "owner-link")
        self.unavailable(fixture.path, "owner")

        fixture = Fixture(self.root / "db-case")
        os.chmod(fixture.dbpath, 0o644)
        self.unavailable(fixture.path, "database")
        os.chmod(fixture.dbpath, 0o600)
        os.link(fixture.dbpath, self.root / "db-link")
        self.unavailable(fixture.path, "database")

    def test_database_and_directory_symlinks_are_rejected(self) -> None:
        fixture = Fixture(self.root)
        original = fixture.dbpath
        moved = self.root / "db-real"
        original.rename(moved)
        original.symlink_to(moved)
        self.unavailable(fixture.path, "database")
        linked = self.root / "store-link"
        linked.symlink_to(fixture.path)
        self.unavailable(linked, "owner")

    def test_unknown_application_version_or_schema_is_unavailable(self) -> None:
        for pragma in ("PRAGMA application_id=7", "PRAGMA user_version=1"):
            case = self.root / str(len(list(self.root.iterdir())))
            case.mkdir()
            fixture = Fixture(case)
            db = sqlite3.connect(fixture.dbpath)
            db.execute(pragma)
            db.commit()
            db.close()
            self.unavailable(fixture.path, "schema")
        case = self.root / "extra-table"
        case.mkdir()
        fixture = Fixture(case)
        db = sqlite3.connect(fixture.dbpath)
        db.execute("CREATE TABLE extra(x)")
        db.commit()
        db.close()
        self.unavailable(fixture.path, "schema")

    def test_corrupt_database_sidecars_and_invalid_counts_are_unavailable(self) -> None:
        case = self.root / "corrupt"
        case.mkdir()
        fixture = Fixture(case)
        fixture.dbpath.write_bytes(b"not sqlite")
        self.unavailable(fixture.path, "query")

        case = self.root / "sidecar"
        case.mkdir()
        fixture = Fixture(case)
        (fixture.path / (SNAPSHOT.DB_NAME + "-wal")).write_bytes(b"present")
        self.unavailable(fixture.path, "sidecar")

        case = self.root / "over-capacity"
        case.mkdir()
        fixture = Fixture(case, capacity=100)
        fixture.add_lease(1, 70, 0)
        fixture.add_lease(2, 70, 1)
        self.unavailable(fixture.path, "counts")

        case = self.root / "invalid-row"
        case.mkdir()
        fixture = Fixture(case)
        db = sqlite3.connect(fixture.dbpath)
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute("INSERT INTO leases VALUES(?, -1, ?, 1, 0)", (bytes(16), bytes(32)))
        db.commit()
        db.close()
        self.unavailable(fixture.path, "counts")

        case = self.root / "invalid-commit-flag"
        case.mkdir()
        fixture = Fixture(case)
        db = sqlite3.connect(fixture.dbpath)
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute("INSERT INTO leases VALUES(?, 97, ?, 1, 2)", (bytes(16), bytes(32)))
        db.commit()
        db.close()
        self.unavailable(fixture.path, "counts")

        case = self.root / "offsetting-invalid-counts"
        case.mkdir()
        fixture = Fixture(case, capacity=100)
        db = sqlite3.connect(fixture.dbpath)
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.executemany("INSERT INTO leases VALUES(?, ?, ?, 1, 0)", (
            (bytes(16), -5, bytes(32)), (bytes([1]) + bytes(15), 5, bytes(32))))
        db.commit()
        db.close()
        self.unavailable(fixture.path, "counts")

        case = self.root / "too-many-leases"
        case.mkdir()
        fixture = Fixture(case)
        db = sqlite3.connect(fixture.dbpath)
        db.executemany("INSERT INTO leases VALUES(?, 0, ?, 1, 0)",
                       ((i.to_bytes(16, "little"), bytes(32)) for i in range(257)))
        db.commit()
        db.close()
        self.unavailable(fixture.path, "counts")

    def test_closed_error_output_does_not_echo_path_or_sqlite_details(self) -> None:
        case = self.root / "private-canary-path"
        case.mkdir()
        fixture = Fixture(case)
        fixture.dbpath.write_bytes(b"private-canary-bytes")
        output = SNAPSHOT.observe(str(fixture.path))
        encoded = json.dumps(output, sort_keys=True)
        self.assertEqual(output["state"], "unavailable")
        self.assertNotIn("private-canary", encoded)
        self.assertNotIn(str(fixture.path), encoded)
        self.assertNotIn("not a database", encoded)


if __name__ == "__main__":
    unittest.main()
