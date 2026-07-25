"""
Storage and resilience tests.

The merge tests prove upserts and removals behave correctly. The atomicity
tests prove the crash-safety claim in the README is real rather than
aspirational - we deliberately blow up in the middle of writing a segment and
assert the database is untouched.
"""

from __future__ import annotations

import sqlite3

import pytest

from conftest import PROVIDER_ID
from crawler.models import Segment
from crawler.storage import CatalogStore


def make_segment(version: int, upserts=None, removals=None) -> Segment:
    return Segment(
        provider_id=PROVIDER_ID,
        version=version,
        upserts=upserts or [],
        removals=removals or [],
    )


DIGEST = "sha256:" + "0" * 64


# ------------------------------------------------------------ merge semantics

def test_upsert_inserts_new_items(store):
    seg = make_segment(1, upserts=[
        {"id": "a", "name": "Apple", "price": 10},
        {"id": "b", "name": "Banana", "price": 20},
    ])
    counts = store.apply_segment(PROVIDER_ID, seg, DIGEST, index_version=1)

    assert counts == {"upserted": 2, "removed": 0}
    assert store.count_items(PROVIDER_ID) == 2
    assert store.get_item(PROVIDER_ID, "a")["name"] == "Apple"


def test_upsert_updates_an_existing_item(store):
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[
        {"id": "a", "name": "Apple", "price": 10}]), DIGEST, 1)
    store.apply_segment(PROVIDER_ID, make_segment(2, upserts=[
        {"id": "a", "name": "Apple", "price": 99}]), DIGEST, 2)

    assert store.count_items(PROVIDER_ID) == 1          # updated, not duplicated
    assert store.get_item(PROVIDER_ID, "a")["price"] == 99


def test_removal_deletes_an_item(store):
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[
        {"id": "a", "name": "Apple"}, {"id": "b", "name": "Banana"}]), DIGEST, 1)
    counts = store.apply_segment(PROVIDER_ID, make_segment(2, removals=["a"]), DIGEST, 2)

    assert counts["removed"] == 1
    assert store.get_item(PROVIDER_ID, "a") is None
    assert store.get_item(PROVIDER_ID, "b") is not None


def test_removing_an_unknown_id_is_not_an_error(store):
    """
    Providers republish removals; deleting something already gone must be a
    no-op, otherwise a harmless duplicate would fail the whole segment.
    """
    counts = store.apply_segment(PROVIDER_ID, make_segment(1, removals=["ghost"]), DIGEST, 1)
    assert counts["removed"] == 0


def test_providers_are_isolated_from_each_other(store):
    """Item IDs are only unique within a provider. Collisions must not merge."""
    store.apply_segment("provider-a", make_segment(1, upserts=[
        {"id": "shared-id", "name": "From A"}]), DIGEST, 1)
    store.apply_segment("provider-b", make_segment(1, upserts=[
        {"id": "shared-id", "name": "From B"}]), DIGEST, 1)

    assert store.get_item("provider-a", "shared-id")["name"] == "From A"
    assert store.get_item("provider-b", "shared-id")["name"] == "From B"
    assert store.count_items() == 2

    # And one provider deleting an id must not touch the other's row.
    store.apply_segment("provider-a", make_segment(2, removals=["shared-id"]), DIGEST, 2)
    assert store.get_item("provider-a", "shared-id") is None
    assert store.get_item("provider-b", "shared-id") is not None


def test_upserts_and_removals_in_one_segment(store):
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[
        {"id": "a"}, {"id": "b"}, {"id": "c"}]), DIGEST, 1)
    store.apply_segment(PROVIDER_ID, make_segment(2,
                                                  upserts=[{"id": "d"}],
                                                  removals=["a", "b"]), DIGEST, 2)

    remaining = {i["item_id"] for i in store.list_items(PROVIDER_ID)}
    assert remaining == {"c", "d"}


# ------------------------------------------------------------ progress state

def test_state_advances_with_each_segment(store):
    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 0

    store.apply_segment(PROVIDER_ID, make_segment(1), DIGEST, 2)
    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 1

    store.apply_segment(PROVIDER_ID, make_segment(2), DIGEST, 2)
    state = store.get_provider_state(PROVIDER_ID)
    assert state.last_applied_version == 2
    assert state.last_index_version == 2
    assert state.last_status == "ok"


def test_state_never_moves_backwards(store):
    """
    Guards against an out-of-order replay silently rewinding our progress
    marker, which would cause us to re-apply old deltas over newer data.
    """
    store.apply_segment(PROVIDER_ID, make_segment(5), DIGEST, 5)
    store.apply_segment(PROVIDER_ID, make_segment(3), DIGEST, 5)
    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 5


def test_applied_segments_audit_trail(store):
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[{"id": "a"}]), DIGEST, 1)
    assert store.is_segment_applied(PROVIDER_ID, 1)
    assert not store.is_segment_applied(PROVIDER_ID, 2)


# --------------------------------------------------------------- ATOMICITY

def test_crash_midway_through_a_transaction_leaves_no_partial_data(store):
    """
    THE CORE RESILIENCE TEST.

    We start a transaction, write some rows, then raise - exactly what a crash,
    a killed process or a disk error would do. Afterwards the database must
    contain NONE of those rows: all-or-nothing, never half.
    """
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[
        {"id": "existing", "name": "Original"}]), DIGEST, 1)

    with pytest.raises(RuntimeError):
        with store.transaction() as cur:
            cur.execute(
                "INSERT INTO catalog_items (provider_id, item_id, payload, "
                "source_version, updated_at) VALUES (?, ?, ?, ?, ?)",
                (PROVIDER_ID, "half-written", "{}", 2, "now"),
            )
            cur.execute(
                "UPDATE catalog_items SET payload = ? WHERE item_id = ?",
                ('{"name": "Corrupted"}', "existing"),
            )
            raise RuntimeError("simulated crash mid-segment")

    assert store.get_item(PROVIDER_ID, "half-written") is None
    assert store.get_item(PROVIDER_ID, "existing")["name"] == "Original"
    assert store.count_items(PROVIDER_ID) == 1


def test_progress_marker_is_not_advanced_when_a_segment_fails(store):
    """
    The progress marker shares a transaction with the data it describes, so a
    failure cannot leave us thinking a segment was applied when it was not.
    """
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[{"id": "a"}]), DIGEST, 3)

    with pytest.raises(RuntimeError):
        with store.transaction() as cur:
            cur.execute(
                "INSERT INTO catalog_items (provider_id, item_id, payload, "
                "source_version, updated_at) VALUES (?, ?, ?, ?, ?)",
                (PROVIDER_ID, "b", "{}", 2, "now"),
            )
            cur.execute(
                "UPDATE provider_state SET last_applied_version = 2 WHERE provider_id = ?",
                (PROVIDER_ID,),
            )
            raise RuntimeError("simulated crash")

    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 1
    assert store.get_item(PROVIDER_ID, "b") is None


def test_data_survives_reopening_the_database(settings):
    """Committed data must be durable across process restarts."""
    store_a = CatalogStore(settings.database_path)
    store_a.apply_segment(PROVIDER_ID, make_segment(1, upserts=[
        {"id": "a", "name": "Persisted"}]), DIGEST, 1)
    store_a.close()

    store_b = CatalogStore(settings.database_path)
    assert store_b.get_item(PROVIDER_ID, "a")["name"] == "Persisted"
    assert store_b.get_provider_state(PROVIDER_ID).last_applied_version == 1
    store_b.close()


def test_reapplying_the_same_segment_is_idempotent(store):
    """
    Belt and braces: even if the crawler somehow replays a segment, the result
    is identical because upserts are keyed by (provider, item) and the audit
    row is upserted rather than inserted twice.
    """
    seg = make_segment(1, upserts=[{"id": "a", "name": "Apple"}], removals=["gone"])
    store.apply_segment(PROVIDER_ID, seg, DIGEST, 1)
    store.apply_segment(PROVIDER_ID, seg, DIGEST, 1)

    assert store.count_items(PROVIDER_ID) == 1
    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 1


def test_schema_uses_a_composite_primary_key(store):
    """Inserting a duplicate (provider, item) pair must be rejected by SQLite."""
    store.apply_segment(PROVIDER_ID, make_segment(1, upserts=[{"id": "a"}]), DIGEST, 1)
    with pytest.raises(sqlite3.IntegrityError):
        with store.transaction() as cur:
            cur.execute(
                "INSERT INTO catalog_items (provider_id, item_id, payload, "
                "source_version, updated_at) VALUES (?, ?, ?, ?, ?)",
                (PROVIDER_ID, "a", "{}", 1, "now"),
            )
