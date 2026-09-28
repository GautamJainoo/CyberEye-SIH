"""
Unit tests for WMSA Database layer.
Verifies schema, FTS5 full-text indexing, and append-only constraints.
"""

import sqlite3
import pytest
from wmsa.db import Database


@pytest.fixture
def db(tmp_path):
    db_file = tmp_path / "test_wmsa.db"
    return Database(db_file)


def test_db_initialization_tables_exist(db):
    with db.get_connection() as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t["name"] for t in tables}

    expected = {
        "scope_manifests",
        "scans",
        "tool_runs",
        "findings",
        "finding_sources",
        "evidence",
        "state_transitions",
        "patches",
        "retests",
        "advisories",
        "feed_syncs",
        "audit_events",
    }
    assert expected.issubset(table_names)


def test_state_transitions_append_only(db):
    # First insert dummy finding to satisfy foreign key
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO findings (finding_id, stable_fingerprint, title, category, status, severity, repo, commit_sha, build_id, scope_id, data_json, created_at, updated_at)
            VALUES ('f-1', 'fp-1', 'Test Finding', 'sast', 'CANDIDATE', 'HIGH', 'worldmonitor', '0d5c618', 'b-1', 's-1', '{}', '2026-09-28T00:00:00Z', '2026-09-28T00:00:00Z')
            """
        )

    t_id = db.record_transition(
        finding_id="f-1",
        from_status="CANDIDATE",
        to_status="TRIAGED",
        actor_type="analyst",
        actor_id="analyst_1",
        reason="Initial triage",
    )
    assert t_id > 0

    # Attempt UPDATE (must be prohibited by trigger)
    with pytest.raises(sqlite3.DatabaseError, match="Updates are prohibited"):
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE state_transitions SET reason = 'Modified reason' WHERE id = ?",
                (t_id,),
            )

    # Attempt DELETE (must be prohibited by trigger)
    with pytest.raises(sqlite3.DatabaseError, match="Deletions are prohibited"):
        with db.get_connection() as conn:
            conn.execute(
                "DELETE FROM state_transitions WHERE id = ?",
                (t_id,),
            )


def test_audit_events_append_only(db):
    event_id = db.log_audit_event(
        event_type="test_event",
        actor_type="system",
        actor_id="test_runner",
        payload={"action": "test"},
    )
    assert event_id > 0

    # Attempt UPDATE
    with pytest.raises(sqlite3.DatabaseError, match="Updates are prohibited"):
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE audit_events SET event_type = 'tampered' WHERE id = ?",
                (event_id,),
            )

    # Attempt DELETE
    with pytest.raises(sqlite3.DatabaseError, match="Deletions are prohibited"):
        with db.get_connection() as conn:
            conn.execute(
                "DELETE FROM audit_events WHERE id = ?",
                (event_id,),
            )


def test_advisories_fts5_indexing(db):
    with db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO advisories (advisory_id, source, title, details, cve_id, fetched_at, content_hash)
            VALUES ('ADV-001', 'OSV', 'Prototype Pollution in Lodash', 'Lodash before 4.17.21 allows prototype injection via merge', 'CVE-2021-23337', '2026-09-28T00:00:00Z', 'hash123')
            """
        )

        # Query FTS virtual table
        results = conn.execute(
            "SELECT advisory_id, title FROM advisories_fts WHERE advisories_fts MATCH 'pollution'"
        ).fetchall()
        assert len(results) == 1
        assert results[0]["advisory_id"] == "ADV-001"

        # Query by CVE in FTS
        cve_results = conn.execute(
            'SELECT advisory_id FROM advisories_fts WHERE advisories_fts MATCH \'"CVE-2021-23337"\''
        ).fetchall()
        assert len(cve_results) == 1
