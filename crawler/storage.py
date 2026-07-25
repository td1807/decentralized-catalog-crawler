"""
Storage layer (SQLite).

WHY SQLITE
----------
The assignment asks us to justify the choice, so the reasoning is spelled out
in full in README.md. The short version: this workload needs *transactions*
(a segment must apply completely or not at all) and *upsert-by-primary-key*
merging. SQLite gives us both with full ACID guarantees, in a single file, with
zero servers to install and no extra dependency - it ships inside Python. Plain
JSON files on disk would have forced us to hand-roll atomicity and would rewrite
the whole catalog for a one-item change; Postgres or MongoDB would be a better
fit at large scale but add operational weight a reviewer should not have to
carry just to run our code.

HOW CRASH SAFETY WORKS HERE
---------------------------
``apply_segment`` wraps three things in ONE transaction:
    1. the upserts,
    2. the removals,
    3. the bookkeeping that records "segment N is now applied".

Because they share a transaction, they share a fate. SQLite writes to a
write-ahead log first and only then marks the transaction committed, so at any
instant the database on disk reflects either the state before the segment or
the state after it - never a half-applied segment. If the process is killed
mid-write, the next connection sees an uncommitted transaction and rolls it
back automatically during recovery.

The crawl state table then makes restart trivial: on the next run we read
``last_applied_version`` and resume from the following segment. That also makes
the crawler *idempotent* - re-running it over already-processed data changes
nothing.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .errors import StorageError
from .models import Segment

SCHEMA = """
-- The aggregated catalog. One row per item per provider.
CREATE TABLE IF NOT EXISTS catalog_items (
    provider_id   TEXT    NOT NULL,
    item_id       TEXT    NOT NULL,
    payload       TEXT    NOT NULL,   -- the item's full JSON document
    source_version INTEGER NOT NULL,  -- segment version that last wrote this row
    updated_at    TEXT    NOT NULL,
    PRIMARY KEY (provider_id, item_id)
);

-- Item IDs are only unique WITHIN a provider, so the primary key is the pair.
-- This also means one provider can never delete or overwrite another's items.

CREATE INDEX IF NOT EXISTS idx_catalog_items_provider
    ON catalog_items (provider_id);

-- Crawl progress. This is what makes restart-after-crash safe.
CREATE TABLE IF NOT EXISTS provider_state (
    provider_id          TEXT    PRIMARY KEY,
    last_applied_version INTEGER NOT NULL DEFAULT 0,
    last_index_version   INTEGER,
    last_crawled_at      TEXT,
    last_status          TEXT
);

-- An audit trail: which segments were applied, when, and with what digest.
-- Doubles as a second layer of idempotency protection.
CREATE TABLE IF NOT EXISTS applied_segments (
    provider_id     TEXT    NOT NULL,
    segment_version INTEGER NOT NULL,
    digest          TEXT    NOT NULL,
    upsert_count    INTEGER NOT NULL,
    removal_count   INTEGER NOT NULL,
    applied_at      TEXT    NOT NULL,
    PRIMARY KEY (provider_id, segment_version)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ProviderState:
    provider_id: str
    last_applied_version: int = 0
    last_index_version: Optional[int] = None
    last_crawled_at: Optional[str] = None
    last_status: Optional[str] = None


class CatalogStore:
    """Thin, explicit wrapper around the SQLite catalog database."""

    def __init__(self, database_path: str):
        self._path = database_path
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(database_path)
        except sqlite3.Error as exc:
            raise StorageError(f"Could not open database {database_path}: {exc}") from exc

        self._conn.row_factory = sqlite3.Row
        # isolation_level=None turns OFF the driver's implicit transaction
        # handling so that WE decide exactly where BEGIN and COMMIT go. That
        # explicitness is the whole point of the crash-safety design.
        self._conn.isolation_level = None

        self._configure()
        self._create_schema()

    # ---------------------------------------------------------------- setup

    def _configure(self) -> None:
        cur = self._conn.cursor()
        # WAL: readers never block the writer, and committed data survives a
        # crash via the write-ahead log.
        cur.execute("PRAGMA journal_mode=WAL;")
        # FULL synchronous: fsync on every commit. Slower, but a committed
        # transaction genuinely survives an OS crash or power loss, which is
        # exactly the durability guarantee this design leans on.
        cur.execute("PRAGMA synchronous=FULL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

    def _create_schema(self) -> None:
        try:
            self._conn.executescript(SCHEMA)
        except sqlite3.Error as exc:
            raise StorageError(f"Could not create schema: {exc}") from exc

    # ----------------------------------------------------------- transaction

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        """
        Run a block of statements as one atomic unit.

        ``BEGIN IMMEDIATE`` takes the write lock up front instead of upgrading
        to it later, which avoids a class of SQLITE_BUSY failures when more
        than one crawler process runs against the same file.
        """
        cursor = self._conn.cursor()
        cursor.execute("BEGIN IMMEDIATE;")
        try:
            yield cursor
        except BaseException:
            # BaseException, not Exception: a KeyboardInterrupt or SystemExit
            # must also roll back rather than leaving a transaction dangling.
            self._conn.rollback()
            raise
        else:
            self._conn.commit()
        finally:
            cursor.close()

    # --------------------------------------------------------------- reading

    def get_provider_state(self, provider_id: str) -> ProviderState:
        row = self._conn.execute(
            "SELECT * FROM provider_state WHERE provider_id = ?", (provider_id,)
        ).fetchone()
        if row is None:
            return ProviderState(provider_id=provider_id)
        return ProviderState(
            provider_id=row["provider_id"],
            last_applied_version=row["last_applied_version"],
            last_index_version=row["last_index_version"],
            last_crawled_at=row["last_crawled_at"],
            last_status=row["last_status"],
        )

    def get_item(self, provider_id: str, item_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT payload FROM catalog_items WHERE provider_id = ? AND item_id = ?",
            (provider_id, item_id),
        ).fetchone()
        return json.loads(row["payload"]) if row else None

    def list_items(self, provider_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if provider_id is None:
            rows = self._conn.execute(
                "SELECT provider_id, item_id, payload FROM catalog_items "
                "ORDER BY provider_id, item_id"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT provider_id, item_id, payload FROM catalog_items "
                "WHERE provider_id = ? ORDER BY item_id",
                (provider_id,),
            ).fetchall()
        return [
            {"provider_id": r["provider_id"], "item_id": r["item_id"], **json.loads(r["payload"])}
            for r in rows
        ]

    def count_items(self, provider_id: Optional[str] = None) -> int:
        if provider_id is None:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM catalog_items").fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM catalog_items WHERE provider_id = ?",
                (provider_id,),
            ).fetchone()
        return int(row["n"])

    def is_segment_applied(self, provider_id: str, segment_version: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM applied_segments WHERE provider_id = ? AND segment_version = ?",
            (provider_id, segment_version),
        ).fetchone()
        return row is not None

    # --------------------------------------------------------------- writing

    def apply_segment(
        self,
        provider_id: str,
        segment: Segment,
        digest: str,
        index_version: int,
    ) -> Dict[str, int]:
        """
        Apply one segment's upserts and removals atomically.

        Everything below happens inside a single transaction, so a crash at any
        point leaves the database exactly as it was before the call.
        """
        applied_at = _now()
        upserted = 0
        removed = 0

        try:
            with self.transaction() as cur:
                for item in segment.upserts:
                    item_id = item["id"]
                    # INSERT ... ON CONFLICT DO UPDATE is SQLite's native
                    # upsert: insert if new, overwrite if the (provider, item)
                    # pair already exists. This is precisely the merge semantic
                    # the assignment describes.
                    cur.execute(
                        """
                        INSERT INTO catalog_items
                            (provider_id, item_id, payload, source_version, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(provider_id, item_id) DO UPDATE SET
                            payload        = excluded.payload,
                            source_version = excluded.source_version,
                            updated_at     = excluded.updated_at
                        """,
                        (
                            provider_id,
                            item_id,
                            json.dumps(item, sort_keys=True, ensure_ascii=False),
                            segment.version,
                            applied_at,
                        ),
                    )
                    upserted += 1

                for item_id in segment.removals:
                    cur.execute(
                        "DELETE FROM catalog_items WHERE provider_id = ? AND item_id = ?",
                        (provider_id, item_id),
                    )
                    removed += cur.rowcount if cur.rowcount > 0 else 0

                cur.execute(
                    """
                    INSERT INTO applied_segments
                        (provider_id, segment_version, digest, upsert_count,
                         removal_count, applied_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(provider_id, segment_version) DO UPDATE SET
                        digest        = excluded.digest,
                        upsert_count  = excluded.upsert_count,
                        removal_count = excluded.removal_count,
                        applied_at    = excluded.applied_at
                    """,
                    (provider_id, segment.version, digest, len(segment.upserts),
                     len(segment.removals), applied_at),
                )

                # The progress marker is committed in the SAME transaction as
                # the data it describes. That is the invariant that makes
                # "resume from last_applied_version + 1" correct: the marker can
                # never be ahead of, or behind, the data.
                cur.execute(
                    """
                    INSERT INTO provider_state
                        (provider_id, last_applied_version, last_index_version,
                         last_crawled_at, last_status)
                    VALUES (?, ?, ?, ?, 'ok')
                    ON CONFLICT(provider_id) DO UPDATE SET
                        last_applied_version =
                            MAX(provider_state.last_applied_version, excluded.last_applied_version),
                        last_index_version = excluded.last_index_version,
                        last_crawled_at    = excluded.last_crawled_at,
                        last_status        = 'ok'
                    """,
                    (provider_id, segment.version, index_version, applied_at),
                )
        except sqlite3.Error as exc:
            raise StorageError(
                f"Failed to apply segment v{segment.version} for {provider_id}: {exc}"
            ) from exc

        return {"upserted": upserted, "removed": removed}

    def record_crawl_result(self, provider_id: str, status: str,
                            index_version: Optional[int] = None) -> None:
        """Record the outcome of a crawl attempt (including failures)."""
        try:
            with self.transaction() as cur:
                cur.execute(
                    """
                    INSERT INTO provider_state
                        (provider_id, last_applied_version, last_index_version,
                         last_crawled_at, last_status)
                    VALUES (?, 0, ?, ?, ?)
                    ON CONFLICT(provider_id) DO UPDATE SET
                        last_index_version =
                            COALESCE(excluded.last_index_version, provider_state.last_index_version),
                        last_crawled_at = excluded.last_crawled_at,
                        last_status     = excluded.last_status
                    """,
                    (provider_id, index_version, _now(), status),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"Could not record crawl result: {exc}") from exc

    # ---------------------------------------------------------------- teardown

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "CatalogStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
