"""
Threat Intelligence and CISA KEV Synchronization Engine for WMSA.
Fetches, caches, and indexes OSV, GHSA, and CISA Known Exploited Vulnerabilities (KEV).
Provides SQLite FTS5 search and exact CVE-to-KEV cross-referencing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

from wmsa.db import Database
from wmsa.normalize import Finding

logger = logging.getLogger("wmsa.intel")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_PUBLIC_URL = "https://api.github.com/advisories?per_page=50"
DEFAULT_TTL_SECONDS = 3600  # 1 hour cache TTL
STALE_THRESHOLD_SECONDS = 86400  # 24 hours considered stale


def _sha256_str(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sanitize_fts_query(query: str) -> str:
    """
    Sanitizes search query for SQLite FTS5.
    Quotes tokens with hyphens/slashes to prevent FTS5 syntax errors (e.g., CVE-2021-23337).
    """
    tokens = re.findall(r'[A-Za-z0-9_\-\.\/]+', query)
    if not tokens:
        return '""'
    return " ".join(f'"{t}"' for t in tokens)


class ThreatIntelManager:
    """Manages threat intelligence feeds, local caching, FTS5 search, and KEV matching."""

    def __init__(
        self,
        db: Optional[Database] = None,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout: float = 15.0,
    ):
        self.db = db or Database()
        self.cache_dir = cache_dir or (Path.cwd() / "data" / "intel_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.timeout = timeout

    def should_sync(self, feed_name: str, force: bool = False) -> bool:
        """Determines if a feed needs synchronization based on cache TTL."""
        if force:
            return True
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT last_sync_time FROM feed_syncs WHERE feed_name = ?",
                (feed_name,),
            ).fetchone()
            if not row:
                return True
            try:
                last_sync = datetime.fromisoformat(row["last_sync_time"])
                delta = (datetime.now(timezone.utc) - last_sync).total_seconds()
                return delta >= self.ttl_seconds
            except Exception:
                return True

    def sync_cisa_kev(self, force: bool = False, source_json_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Synchronizes CISA Known Exploited Vulnerabilities catalog.
        Supports fetching from official URL or reading an offline JSON fixture.
        """
        feed_name = "cisa-kev"
        now = datetime.now(timezone.utc).isoformat()

        if not self.should_sync(feed_name, force) and not source_json_path:
            with self.db.get_connection() as conn:
                row = conn.execute("SELECT record_count FROM feed_syncs WHERE feed_name = ?", (feed_name,)).fetchone()
                count = row["record_count"] if row else 0
            return {"feed": feed_name, "status": "CACHED", "count": count, "synced_at": now}

        data = None
        if source_json_path and source_json_path.exists():
            with open(source_json_path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        else:
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(CISA_KEV_URL)
                    resp.raise_for_status()
                    data = resp.json()
            except Exception as e:
                logger.warning(f"Failed to fetch CISA KEV catalog online: {e}")
                # Record error in feed_syncs
                with self.db.get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO feed_syncs (feed_name, last_sync_time, record_count, status, metadata_json)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(feed_name) DO UPDATE SET
                            status = 'STALE_FETCH_ERROR',
                            metadata_json = json_object('error', ?)
                        """,
                        (feed_name, now, 0, "STALE_FETCH_ERROR", json.dumps({"error": str(e)}), str(e)),
                    )
                return {"feed": feed_name, "status": "FAILED", "error": str(e), "synced_at": now}

        vulnerabilities = data.get("vulnerabilities", [])
        raw_sha = _sha256_str(json.dumps(data, sort_keys=True))

        inserted_count = 0
        with self.db.get_connection() as conn:
            for item in vulnerabilities:
                cve_id = item.get("cveID", "").strip().upper()
                if not cve_id:
                    continue
                advisory_id = f"KEV-{cve_id}"
                title = f"{item.get('vendorProject', '')} {item.get('product', '')}: {item.get('vulnerabilityName', '')}".strip()
                details = item.get("shortDescription", "")
                date_added = item.get("dateAdded", "")

                conn.execute(
                    """
                    INSERT INTO advisories (
                        advisory_id, source, title, details, cve_id, ghsa_id,
                        kev_match, published_at, updated_at, fetched_at, content_hash
                    )
                    VALUES (?, 'CISA-KEV', ?, ?, ?, NULL, 1, ?, ?, ?, ?)
                    ON CONFLICT(advisory_id) DO UPDATE SET
                        title = excluded.title,
                        details = excluded.details,
                        cve_id = excluded.cve_id,
                        kev_match = 1,
                        updated_at = excluded.updated_at,
                        fetched_at = excluded.fetched_at,
                        content_hash = excluded.content_hash
                    """,
                    (advisory_id, title, details, cve_id, date_added, date_added, now, raw_sha),
                )
                inserted_count += 1

            conn.execute(
                """
                INSERT INTO feed_syncs (feed_name, last_sync_time, record_count, status, metadata_json)
                VALUES (?, ?, ?, 'OK', ?)
                ON CONFLICT(feed_name) DO UPDATE SET
                    last_sync_time = excluded.last_sync_time,
                    record_count = excluded.record_count,
                    status = 'OK',
                    metadata_json = excluded.metadata_json
                """,
                (
                    feed_name,
                    now,
                    inserted_count,
                    json.dumps({
                        "catalog_version": data.get("catalogVersion", "unknown"),
                        "date_released": data.get("dateReleased", now),
                        "content_sha256": raw_sha,
                    }),
                ),
            )

        return {"feed": feed_name, "status": "OK", "count": inserted_count, "synced_at": now}

    def sync_ghsa(self, force: bool = False, source_json_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Synchronizes GitHub Global Security Advisories.
        Supports public GitHub REST API or offline JSON fixture.
        """
        feed_name = "ghsa"
        now = datetime.now(timezone.utc).isoformat()

        if not self.should_sync(feed_name, force) and not source_json_path:
            with self.db.get_connection() as conn:
                row = conn.execute("SELECT record_count FROM feed_syncs WHERE feed_name = ?", (feed_name,)).fetchone()
                count = row["record_count"] if row else 0
            return {"feed": feed_name, "status": "CACHED", "count": count, "synced_at": now}

        data = None
        if source_json_path and source_json_path.exists():
            with open(source_json_path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        else:
            try:
                headers = {"Accept": "application/vnd.github+json", "User-Agent": "WMSA-Security-Scanner"}
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(GHSA_PUBLIC_URL, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
            except Exception as e:
                logger.warning(f"Failed to fetch GHSA feed online: {e}")
                with self.db.get_connection() as conn:
                    conn.execute(
                        """
                        INSERT INTO feed_syncs (feed_name, last_sync_time, record_count, status, metadata_json)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(feed_name) DO UPDATE SET
                            status = 'STALE_FETCH_ERROR',
                            metadata_json = json_object('error', ?)
                        """,
                        (feed_name, now, 0, "STALE_FETCH_ERROR", json.dumps({"error": str(e)}), str(e)),
                    )
                return {"feed": feed_name, "status": "FAILED", "error": str(e), "synced_at": now}

        if not isinstance(data, list):
            data = [data]

        inserted_count = 0
        raw_sha = _sha256_str(json.dumps(data, sort_keys=True))

        with self.db.get_connection() as conn:
            for item in data:
                ghsa_id = item.get("ghsa_id") or item.get("id")
                if not ghsa_id:
                    continue
                advisory_id = str(ghsa_id)
                cve_id = item.get("cve_id")
                title = item.get("summary") or item.get("title") or "Advisory"
                details = item.get("description") or item.get("details") or ""
                pub_at = item.get("published_at")
                upd_at = item.get("updated_at")

                # Check if CVE is already known in KEV
                kev_match = 0
                if cve_id:
                    kev_row = conn.execute(
                        "SELECT 1 FROM advisories WHERE source = 'CISA-KEV' AND UPPER(cve_id) = UPPER(?)",
                        (cve_id.strip(),),
                    ).fetchone()
                    if kev_row:
                        kev_match = 1

                conn.execute(
                    """
                    INSERT INTO advisories (
                        advisory_id, source, title, details, cve_id, ghsa_id,
                        kev_match, published_at, updated_at, fetched_at, content_hash
                    )
                    VALUES (?, 'GHSA', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(advisory_id) DO UPDATE SET
                        title = excluded.title,
                        details = excluded.details,
                        cve_id = excluded.cve_id,
                        ghsa_id = excluded.ghsa_id,
                        kev_match = excluded.kev_match,
                        updated_at = excluded.updated_at,
                        fetched_at = excluded.fetched_at,
                        content_hash = excluded.content_hash
                    """,
                    (advisory_id, title, details, cve_id, ghsa_id, kev_match, pub_at, upd_at, now, raw_sha),
                )
                inserted_count += 1

            conn.execute(
                """
                INSERT INTO feed_syncs (feed_name, last_sync_time, record_count, status, metadata_json)
                VALUES (?, ?, ?, 'OK', ?)
                ON CONFLICT(feed_name) DO UPDATE SET
                    last_sync_time = excluded.last_sync_time,
                    record_count = excluded.record_count,
                    status = 'OK',
                    metadata_json = excluded.metadata_json
                """,
                (feed_name, now, inserted_count, json.dumps({"content_sha256": raw_sha})),
            )

        return {"feed": feed_name, "status": "OK", "count": inserted_count, "synced_at": now}

    def sync_all(self, force: bool = False) -> Dict[str, Any]:
        """Syncs all feeds (CISA-KEV and GHSA)."""
        kev_res = self.sync_cisa_kev(force=force)
        ghsa_res = self.sync_ghsa(force=force)
        return {
            "cisa_kev": kev_res,
            "ghsa": ghsa_res,
        }

    def is_cve_in_kev(self, cve_id: str) -> bool:
        """
        NON-NEGOTIABLE: Exact match only against local CISA KEV catalog.
        Never fuzzy or partial match.
        """
        clean_cve = cve_id.strip().upper()
        if not clean_cve:
            return False
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM advisories WHERE source = 'CISA-KEV' AND UPPER(cve_id) = ? LIMIT 1",
                (clean_cve,),
            ).fetchone()
            return row is not None

    def get_kev_cves(self) -> Set[str]:
        """Returns the set of all known CISA KEV CVE IDs in the local database."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT UPPER(cve_id) as cve FROM advisories WHERE source = 'CISA-KEV' AND cve_id IS NOT NULL"
            ).fetchall()
            return {r["cve"] for r in rows if r["cve"]}

    def cross_reference_finding(self, finding: Finding) -> bool:
        """
        Checks finding's CVE identifiers against the local CISA KEV catalog.
        Sets finding.kev_match = True only on exact match.
        """
        for cve in finding.cve:
            if self.is_cve_in_kev(cve):
                finding.kev_match = True
                return True
        return False

    def search_advisories(self, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Full-text search in SQLite FTS5 advisories index.
        Safely sanitizes query terms to prevent FTS5 syntax errors.
        """
        fts_query = _sanitize_fts_query(query)
        if not fts_query.strip():
            return []

        results = []
        with self.db.get_connection() as conn:
            try:
                rows = conn.execute(
                    """
                    SELECT a.*
                    FROM advisories a
                    JOIN advisories_fts fts ON a.rowid = fts.rowid
                    WHERE advisories_fts MATCH ?
                    ORDER BY a.kev_match DESC, a.fetched_at DESC
                    LIMIT ?
                    """,
                    (fts_query, limit),
                ).fetchall()
                results = [dict(r) for r in rows]
            except Exception as e:
                logger.error(f"FTS5 query failed for '{fts_query}': {e}")
                # Fallback to LIKE if FTS expression fails
                rows = conn.execute(
                    """
                    SELECT * FROM advisories
                    WHERE title LIKE ? OR details LIKE ? OR cve_id LIKE ?
                    ORDER BY kev_match DESC, fetched_at DESC
                    LIMIT ?
                    """,
                    (f"%{query}%", f"%{query}%", f"%{query}%", limit),
                ).fetchall()
                results = [dict(r) for r in rows]

        return results

    def get_feed_statuses(self) -> List[Dict[str, Any]]:
        """Returns the freshness and sync status of all threat intel feeds."""
        statuses = []
        now = datetime.now(timezone.utc)
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM feed_syncs ORDER BY feed_name ASC").fetchall()
            for r in rows:
                item = dict(r)
                item["metadata"] = json.loads(item["metadata_json"]) if item.get("metadata_json") else {}
                try:
                    last_sync = datetime.fromisoformat(item["last_sync_time"])
                    age_seconds = (now - last_sync).total_seconds()
                    item["age_seconds"] = int(age_seconds)
                    item["is_stale"] = age_seconds > STALE_THRESHOLD_SECONDS
                except Exception:
                    item["age_seconds"] = None
                    item["is_stale"] = True
                statuses.append(item)
        return statuses
