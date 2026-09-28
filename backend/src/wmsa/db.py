"""
Database and Migration Layer for WMSA.
Supports PostgreSQL as primary database (via psycopg 3) with fallback to SQLite.
Includes FTS full-text search and append-only audit & state transition tables.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("wmsa.db")

from wmsa.paths import get_base_dir

POSTGRES_SCHEMA_SQL = """
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
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    command_line TEXT NOT NULL,
    exit_code INTEGER NOT NULL,
    raw_output_path TEXT NOT NULL,
    raw_output_sha256 TEXT NOT NULL,
    peak_ram_mb REAL,
    duration_seconds REAL,
    created_at TEXT NOT NULL
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
    id SERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    tool_version TEXT,
    rule_id TEXT,
    snippet_hash TEXT,
    raw_ref TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    recipe_id TEXT,
    artifact_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS state_transitions (
    id SERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION prevent_modifications_transitions()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Updates or deletions are prohibited on append-only state_transitions table';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_update_transitions ON state_transitions;
CREATE TRIGGER trg_prevent_update_transitions
BEFORE UPDATE OR DELETE ON state_transitions
FOR EACH ROW EXECUTE FUNCTION prevent_modifications_transitions();

CREATE TABLE IF NOT EXISTS patches (
    patch_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    branch_name TEXT NOT NULL,
    diff_content TEXT NOT NULL,
    patch_commit_sha TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS retests (
    retest_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id),
    patch_id TEXT,
    recipe_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    original_evidence_hash TEXT NOT NULL,
    retest_evidence_hash TEXT NOT NULL,
    details_json TEXT,
    timestamp TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS audit_events (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION prevent_modifications_audit()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Updates or deletions are prohibited on append-only audit_events table';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_update_audit ON audit_events;
CREATE TRIGGER trg_prevent_update_audit
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION prevent_modifications_audit();

CREATE TABLE IF NOT EXISTS feed_syncs (
    feed_name TEXT PRIMARY KEY,
    last_sync_time TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT,
    content_hash TEXT,
    updated_at TEXT
);
"""

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
    tool_version TEXT,
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
    metadata_json TEXT,
    content_hash TEXT,
    updated_at TEXT
);

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


class PostgresCursorWrapper:
    """Wraps psycopg.Cursor to provide dict-like rows and lastrowid matching sqlite3.Cursor."""

    def __init__(self, cur, lastrowid: int = 0):
        self._cur = cur
        self._lastrowid = lastrowid

    def fetchone(self) -> Optional[Dict[str, Any]]:
        row = self._cur.fetchone()
        return row

    def fetchall(self) -> List[Dict[str, Any]]:
        return self._cur.fetchall()

    @property
    def lastrowid(self) -> int:
        return self._lastrowid

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount


class PostgresConnectionWrapper:
    """Wraps psycopg connection to accept SQLite-style ? placeholders and auto-translate syntax."""

    def __init__(self, dsn: str):
        import psycopg
        from psycopg.rows import dict_row
        self.raw_conn = psycopg.connect(dsn, row_factory=dict_row)

    def execute(self, sql: str, params: Optional[Any] = None) -> PostgresCursorWrapper:
        # Translate placeholder ? -> %s
        tsql = sql.replace("?", "%s")

        # Translate SQLite FTS join query for advisories
        if "advisories_fts" in tsql:
            # Match query replacement
            clean_q = params[0] if params else ""
            clean_limit = params[1] if params and len(params) > 1 else 50
            if isinstance(clean_q, str):
                clean_q = clean_q.replace('"', '').strip()
            like_val = f"%{clean_q}%"
            tsql = """
            SELECT a.advisory_id, a.source, a.title, a.details, a.cve_id, a.ghsa_id, a.kev_match
            FROM advisories a
            WHERE (a.title ILIKE %s OR a.details ILIKE %s OR a.cve_id ILIKE %s)
            ORDER BY a.kev_match DESC, a.published_at DESC
            LIMIT %s
            """
            params = (like_val, like_val, like_val, clean_limit)

        # Translate SQLite INSERT OR REPLACE for scope_manifests
        if "INSERT OR REPLACE INTO scope_manifests" in tsql:
            tsql = (
                "INSERT INTO scope_manifests (id, manifest_yaml, commit_sha, approved_by, approved_at, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT (id) DO UPDATE SET "
                "manifest_yaml = EXCLUDED.manifest_yaml, commit_sha = EXCLUDED.commit_sha, "
                "approved_by = EXCLUDED.approved_by, approved_at = EXCLUDED.approved_at, "
                "created_at = EXCLUDED.created_at"
            )

        # Handle lastrowid for auto-increment tables
        lastrowid = 0
        needs_returning = False
        upper_sql = tsql.strip().upper()
        if (
            upper_sql.startswith("INSERT INTO AUDIT_EVENTS")
            or upper_sql.startswith("INSERT INTO STATE_TRANSITIONS")
            or upper_sql.startswith("INSERT INTO FINDING_SOURCES")
        ) and "RETURNING" not in upper_sql:
            tsql = tsql.rstrip(";") + " RETURNING id;"
            needs_returning = True

        cur = self.raw_conn.cursor()
        if params is not None:
            cur.execute(tsql, params)
        else:
            cur.execute(tsql)

        if needs_returning:
            row = cur.fetchone()
            if row and "id" in row:
                lastrowid = row["id"]

        return PostgresCursorWrapper(cur, lastrowid=lastrowid)

    def executescript(self, script: str) -> None:
        with self.raw_conn.cursor() as cur:
            cur.execute(script)

    def commit(self) -> None:
        self.raw_conn.commit()

    def rollback(self) -> None:
        self.raw_conn.rollback()

    def close(self) -> None:
        self.raw_conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        self.close()


class Database:
    """
    Manages database connection and operations.
    Primary engine: PostgreSQL (via psycopg 3).
    Fallback engine: SQLite (wmsa.db).
    """

    def __init__(
        self,
        db_path: Optional[Path | str] = None,
        database_url: Optional[str] = None,
    ):
        self.db_path = Path(db_path) if db_path else (get_base_dir() / "wmsa.db")
        self.database_url = database_url or os.getenv("DATABASE_URL", "dbname=wmsa")
        self.backend_type = "postgres"

        # If a specific .db path is passed for test fixtures, respect SQLite
        if db_path and str(db_path).endswith(".db"):
            self.backend_type = "sqlite"
        else:
            # Check PostgreSQL connectivity
            try:
                import psycopg
                from psycopg.rows import dict_row
                conn = psycopg.connect(self.database_url, row_factory=dict_row)
                conn.close()
                self.backend_type = "postgres"
            except Exception as e:
                logger.info(f"PostgreSQL connection unavailable ({e}); falling back to SQLite.")
                self.backend_type = "sqlite"

        self.init_db()

    def get_connection(self):
        if self.backend_type == "postgres":
            return PostgresConnectionWrapper(self.database_url)
        else:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON;")
            return conn

    def init_db(self) -> None:
        if self.backend_type == "postgres":
            with self.get_connection() as conn:
                conn.executescript(POSTGRES_SCHEMA_SQL)
        else:
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

    def purge_assessment_data(self) -> Dict[str, int]:
        """Purges all finding, scan, evidence, and lifecycle records to restore clean slate."""
        c_findings = 0
        manifest_rows = []

        if self.backend_type == "postgres":
            with self.get_connection() as conn:
                row = conn.execute("SELECT count(*) as c FROM findings").fetchone()
                c_findings = row["c"] if row else 0
                manifests = conn.execute("SELECT * FROM scope_manifests").fetchall()
                manifest_rows = [dict(m) for m in manifests]

                # Drop and recreate tables to respect triggers and cleanly reset
                conn.executescript("""
                DROP TABLE IF EXISTS finding_sources CASCADE;
                DROP TABLE IF EXISTS evidence CASCADE;
                DROP TABLE IF EXISTS state_transitions CASCADE;
                DROP TABLE IF EXISTS patches CASCADE;
                DROP TABLE IF EXISTS retests CASCADE;
                DROP TABLE IF EXISTS tool_runs CASCADE;
                DROP TABLE IF EXISTS scans CASCADE;
                DROP TABLE IF EXISTS findings CASCADE;
                DROP TABLE IF EXISTS audit_events CASCADE;
                """)
            self.init_db()

            if manifest_rows:
                with self.get_connection() as conn:
                    for m in manifest_rows:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO scope_manifests (id, manifest_yaml, commit_sha, approved_by, approved_at, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (m["id"], m["manifest_yaml"], m["commit_sha"], m["approved_by"], m["approved_at"], m["created_at"]),
                        )
            return {"purged_findings": c_findings}

        # SQLite fallback
        if self.db_path.exists():
            try:
                with self.get_connection() as conn:
                    c_findings = conn.execute("SELECT count(*) as c FROM findings").fetchone()["c"]
                    manifests = conn.execute("SELECT * FROM scope_manifests").fetchall()
                    manifest_rows = [dict(m) for m in manifests]
            except Exception:
                pass
            self.db_path.unlink(missing_ok=True)

        self.init_db()

        if manifest_rows:
            with self.get_connection() as conn:
                for m in manifest_rows:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO scope_manifests (id, manifest_yaml, commit_sha, approved_by, approved_at, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (m["id"], m["manifest_yaml"], m["commit_sha"], m["approved_by"], m["approved_at"], m["created_at"]),
                    )

        return {"purged_findings": c_findings}
