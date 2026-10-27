"""Local persistence: a single SQLite file in the project.

No server, no network — the whole history lives in one file you own. This is
the collapsed-in-local version of what would be PostgreSQL in a hosted build;
the shape of the data is identical, so it can be promoted later without a
rewrite.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .findings import Finding, Severity, now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    profile      TEXT NOT NULL,
    intensity    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running',
    started_at   TEXT NOT NULL,
    finished_at  TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    source       TEXT NOT NULL,
    target       TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    category     TEXT NOT NULL,
    title        TEXT NOT NULL,
    resource     TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    remediation  TEXT NOT NULL DEFAULT '',
    refs         TEXT NOT NULL DEFAULT '[]',
    raw          TEXT NOT NULL DEFAULT '{}',
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(target, fingerprint);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- scans ------------------------------------------------------------
    def start_scan(self, target: str, profile: str, intensity: str) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO scans(target, profile, intensity, status, started_at) "
                "VALUES (?,?,?,'running',?)",
                (target, profile, intensity, now_iso()),
            )
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str = "done") -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE scans SET status=?, finished_at=? WHERE id=?",
                (status, now_iso(), scan_id),
            )

    def latest_scan_id(self, target: str) -> int | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id FROM scans WHERE target=? AND status='done' "
                "ORDER BY id DESC LIMIT 1",
                (target,),
            ).fetchone()
            return int(row["id"]) if row else None

    def scans(self, target: str | None = None, limit: int = 50) -> list[dict]:
        q = "SELECT * FROM scans"
        args: tuple = ()
        if target:
            q += " WHERE target=?"
            args = (target,)
        q += " ORDER BY id DESC LIMIT ?"
        args += (limit,)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]

    # -- findings ---------------------------------------------------------
    def add_finding(self, scan_id: int, f: Finding) -> None:
        fp = f.fingerprint
        with self._conn() as c:
            # Carry first_seen forward from the earliest time we ever saw this
            # fingerprint for this target, so trend data survives across scans.
            prev = c.execute(
                "SELECT MIN(first_seen) AS fs FROM findings WHERE target=? AND fingerprint=?",
                (f.target, fp),
            ).fetchone()
            now = now_iso()
            first_seen = prev["fs"] if prev and prev["fs"] else now
            c.execute(
                "INSERT INTO findings(scan_id, fingerprint, source, target, severity, "
                "category, title, resource, description, remediation, refs, raw, "
                "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    scan_id, fp, f.source, f.target, int(f.severity), f.category,
                    f.title, f.resource, f.description, f.remediation,
                    json.dumps(f.references, ensure_ascii=False),
                    json.dumps(f.raw, ensure_ascii=False),
                    first_seen, now,
                ),
            )

    def findings(self, scan_id: int) -> list[Finding]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY severity DESC, source",
                (scan_id,),
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    @staticmethod
    def _row_to_finding(r: sqlite3.Row) -> Finding:
        return Finding(
            source=r["source"],
            target=r["target"],
            severity=Severity(r["severity"]),
            category=r["category"],
            title=r["title"],
            resource=r["resource"],
            description=r["description"],
            remediation=r["remediation"],
            references=json.loads(r["refs"]),
            raw=json.loads(r["raw"]),
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
        )

    # -- diff -------------------------------------------------------------
    def diff(self, target: str) -> dict[str, list[Finding]]:
        """Compare the two most recent completed scans of a target.

        Returns {"new": [...], "resolved": [...], "unchanged": [...]} keyed by
        fingerprint, which is exactly the "today vs yesterday" view.
        """
        done = [s["id"] for s in self.scans(target) if s["status"] == "done"]
        if not done:
            return {"new": [], "resolved": [], "unchanged": []}
        current = self.findings(done[0])
        previous = self.findings(done[1]) if len(done) > 1 else []
        cur = {f.fingerprint: f for f in current}
        prev = {f.fingerprint: f for f in previous}
        return {
            "new": [f for fp, f in cur.items() if fp not in prev],
            "resolved": [f for fp, f in prev.items() if fp not in cur],
            "unchanged": [f for fp, f in cur.items() if fp in prev],
        }
