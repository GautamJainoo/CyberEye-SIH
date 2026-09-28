"""
SQLite Database and Migration Layer for WMSA.
Includes FTS5 full-text search and append-only audit & state transition tables.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scope_manifests (
    id TEXT PRIMARY KEY,
    manifest_yaml TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    metrics_json TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_runs (
    run_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    command_line TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    raw_output_path TEXT NOT NULL,
    raw_output_sha256 TEXT NOT NULL,
    peak_ram_mb REAL,
    duration_seconds REAL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    stable_fingerprint TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    repo TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    build_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    rule_id TEXT,
    snippet_hash TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    recipe_id TEXT,
    artifact_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id) ON DELETE CASCADE
);

-- APPEND-ONLY: State transitions cannot be modified or deleted once written
CREATE TABLE IF NOT EXISTS state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TRIGGER IF NOT EXISTS trg_prevent_update_transitions
BEFORE UPDATE ON state_transitions
BEGIN
    SELECT RAISE(FAIL, 'Updates are prohibited on append-only state_transitions table');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_delete_transitions
BEFORE DELETE ON state_transitions
BEGIN
    SELECT RAISE(FAIL, 'Deletions are prohibited on append-only state_transitions table');
END;

CREATE TABLE IF NOT EXISTS patches (
    patch_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    branch_name TEXT NOT NULL,
    diff_content TEXT NOT NULL,
    patch_commit_sha TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS retests (
    retest_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    patch_id TEXT,
    recipe_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    original_evidence_hash TEXT NOT NULL,
    retest_evidence_hash TEXT NOT NULL,
    details_json TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT,
    cve_id TEXT,
    ghsa_id TEXT,
    kev_match INTEGER DEFAULT 0,
    published_at TEXT,
    updated_at TEXT,
    fetched_at TEXT NOT NULL,
    content_hash TEXT NOT NULL
);

-- SQLite FTS5 Full-Text Search Virtual Table
CREATE VIRTUAL TABLE IF NOT EXISTS advisories_fts USING fts5(
    advisory_id,
    title,
    details,
    cve_id,
    content='advisories',
    content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS advisories_ai AFTER INSERT ON advisories BEGIN
  INSERT INTO advisories_fts(rowid, advisory_id, title, details, cve_id)
  VALUES (new.rowid, new.advisory_id, new.title, new.details, new.cve_id);
END;

CREATE TRIGGER IF NOT EXISTS advisories_ad AFTER DELETE ON advisories BEGIN
  INSERT INTO advisories_fts(advisories_fts, rowid, advisory_id, title, details, cve_id)
  VALUES('delete', old.rowid, old.advisory_id, old.title, old.details, old.cve_id);
END;

CREATE TRIGGER IF NOT EXISTS advisories_au AFTER UPDATE ON advisories BEGIN
  INSERT INTO advisories_fts(advisories_fts, rowid, advisory_id, title, details, cve_id)
  VALUES('delete', old.rowid, old.advisory_id, old.title, old.details, old.cve_id);
  INSERT INTO advisories_fts(rowid, advisory_id, title, details, cve_id)
  VALUES (new.rowid, new.advisory_id, new.title, new.details, new.cve_id);
END;

CREATE TABLE IF NOT EXISTS feed_syncs (
    feed_name TEXT PRIMARY KEY,
    last_sync_time TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT
);

-- APPEND-ONLY: Audit events table
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS trg_prevent_update_audit
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(FAIL, 'Updates are prohibited on append-only audit_events table');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_delete_audit
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(FAIL, 'Deletions are prohibited on append-only audit_events table');
END;
"""


class Database:
    """Manages SQLite database connection and operations."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (Path.cwd() / "wmsa.db")
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)

    def log_audit_event(
        self, event_type: str, actor_type: str, actor_id: str, payload: Dict[str, Any]
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO audit_events (event_type, actor_type, actor_id, payload_json, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, actor_type, actor_id, json.dumps(payload), now),
            )
            return cur.lastrowid or 0

    def record_transition(
        self,
        finding_id: str,
        from_status: str,
        to_status: str,
        actor_type: str,
        actor_id: str,
        reason: str,
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO state_transitions (finding_id, from_status, to_status, actor_type, actor_id, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (finding_id, from_status, to_status, actor_type, actor_id, reason, now),
            )
            return cur.lastrowid or 0

    def save_scope_manifest(
        self, scope_id: str, manifest_yaml: str, commit_sha: str, approved_by: str, approved_at: str
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scope_manifests (id, manifest_yaml, commit_sha, approved_by, approved_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scope_id, manifest_yaml, commit_sha, approved_by, approved_at, now),
            )
