"""
End-to-end crawler tests.

These drive the real Crawler against a real signed provider over ``file://``
URLs: config -> fetch -> verify signature -> verify digest -> store. No
component is mocked, so a passing run here means the whole pipeline works.
"""

from __future__ import annotations

import json

import pytest

from conftest import PROVIDER_ID, MockProvider, segment
from crawler.config import Config, CrawlerSettings, ProviderConfig, load_config
from crawler.crawler import Crawler
from crawler.errors import ConfigError
from crawler.fetcher import Fetcher
from crawler.storage import CatalogStore


def run_crawl(config: Config, store: CatalogStore):
    with Fetcher(config.settings) as fetcher:
        return Crawler(config, store, fetcher).run()


# ------------------------------------------------------------------ happy path

def test_full_crawl_applies_all_segments(provider, store, make_config):
    provider.publish([
        segment(1, upserts=[{"id": "a", "name": "Apple", "price": 10},
                            {"id": "b", "name": "Banana", "price": 20}]),
        segment(2, upserts=[{"id": "a", "name": "Apple", "price": 15},
                            {"id": "c", "name": "Cherry", "price": 30}],
                removals=["b"]),
    ])

    report = run_crawl(make_config(provider), store)
    result = report.results[0]

    assert result.status == "ok"
    assert result.segments_applied == [1, 2]
    assert {i["item_id"] for i in store.list_items(PROVIDER_ID)} == {"a", "c"}
    assert store.get_item(PROVIDER_ID, "a")["price"] == 15


def test_second_run_is_a_no_op(provider, store, make_config):
    provider.publish([segment(1, upserts=[{"id": "a"}])])
    config = make_config(provider)

    run_crawl(config, store)
    report = run_crawl(config, store)

    assert report.results[0].status == "up-to-date"
    assert report.results[0].segments_applied == []


def test_incremental_publish_only_fetches_the_new_segment(provider, store, make_config):
    """The whole point of the version marker: do not re-download history."""
    config = make_config(provider)

    provider.publish([segment(1, upserts=[{"id": "a"}])])
    run_crawl(config, store)

    provider.publish([
        segment(1, upserts=[{"id": "a"}]),
        segment(2, upserts=[{"id": "b"}]),
    ])
    report = run_crawl(config, store)

    assert report.results[0].segments_applied == [2]   # not [1, 2]
    assert store.count_items(PROVIDER_ID) == 2


# ------------------------------------------------------------ failure handling

def test_tampered_segment_stops_the_crawl_and_writes_nothing(provider, store, make_config):
    """
    Fail closed. A digest mismatch must abort before anything is stored - we
    never accept "most of the data looks fine".
    """
    provider.publish([segment(1, upserts=[{"id": "a", "name": "Apple", "price": 10}])])
    provider.tamper_segment(1, lambda d: d["upserts"][0].update({"price": 1}))

    report = run_crawl(make_config(provider), store)

    assert report.results[0].status == "failed"
    assert "digest mismatch" in report.results[0].error
    assert store.count_items(PROVIDER_ID) == 0
    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 0


def test_tampered_index_stops_the_crawl(provider, store, make_config):
    provider.publish([segment(1, upserts=[{"id": "a"}])])
    index = provider.read_index()
    index["payload"]["version"] = 42
    provider.write_index_raw(index)

    report = run_crawl(make_config(provider), store)

    assert report.results[0].status == "failed"
    assert "SIGNATURE VERIFICATION FAILED" in report.results[0].error
    assert store.count_items(PROVIDER_ID) == 0


def test_earlier_segments_survive_a_later_failure(provider, store, make_config):
    """
    Segments commit one at a time. If v2 is corrupt, v1 stays applied and the
    marker sits at 1, so the next run retries only v2.
    """
    provider.publish([
        segment(1, upserts=[{"id": "a", "name": "Good"}]),
        segment(2, upserts=[{"id": "b", "name": "Also good"}]),
    ])
    provider.tamper_segment(2, lambda d: d["upserts"][0].update({"name": "Tampered"}))

    report = run_crawl(make_config(provider), store)

    assert report.results[0].status == "failed"
    assert report.results[0].segments_applied == [1]
    assert store.get_item(PROVIDER_ID, "a") is not None
    assert store.get_item(PROVIDER_ID, "b") is None
    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 1


def test_crawl_resumes_after_an_interruption(provider, store, make_config):
    """
    RESILIENCE, END TO END.

    Simulate a crash after v1 committed but before v2 did, then restart. The
    crawler must resume at v2 and must not re-apply v1.
    """
    provider.publish([
        segment(1, upserts=[{"id": "a", "name": "First"}]),
        segment(2, upserts=[{"id": "b", "name": "Second"}]),
    ])
    config = make_config(provider)

    # Crash: allow v1 through, then blow up inside segment v2.
    crawler = Crawler(config, store, Fetcher(config.settings))
    original_apply = crawler._apply_segment

    def crash_on_v2(provider_cfg, index_url, ref, index_version):
        if ref.version == 2:
            raise KeyboardInterrupt("power cut")
        return original_apply(provider_cfg, index_url, ref, index_version)

    crawler._apply_segment = crash_on_v2
    with pytest.raises(KeyboardInterrupt):
        crawler.run()

    assert store.get_provider_state(PROVIDER_ID).last_applied_version == 1
    assert store.get_item(PROVIDER_ID, "b") is None

    # Restart: a brand-new store object, as a fresh process would have.
    store_after_restart = CatalogStore(config.settings.database_path)
    report = run_crawl(config, store_after_restart)

    assert report.results[0].segments_applied == [2]
    assert store_after_restart.get_item(PROVIDER_ID, "a")["name"] == "First"
    assert store_after_restart.get_item(PROVIDER_ID, "b")["name"] == "Second"
    store_after_restart.close()


def test_missing_provider_files_fail_gracefully(store, settings, tmp_path):
    config = Config(
        settings=settings,
        providers=[ProviderConfig(provider_id=PROVIDER_ID,
                                  manifest_url=str(tmp_path / "nope" / "manifest.json"))],
    )
    report = run_crawl(config, store)
    assert report.results[0].status == "failed"
    assert len(report.failed) == 1


def test_one_bad_provider_does_not_stop_the_others(tmp_path, store, settings):
    """Failure isolation: providers are independent."""
    good = MockProvider(tmp_path / "good", provider_id="good-provider")
    good.publish([segment(1, upserts=[{"id": "a"}], provider_id="good-provider")])

    bad = MockProvider(tmp_path / "bad", provider_id="bad-provider")
    bad.publish([segment(1, upserts=[{"id": "z"}], provider_id="bad-provider")])
    bad.tamper_segment(1, lambda d: d["upserts"].append({"id": "injected"}))

    config = Config(settings=settings, providers=[
        ProviderConfig(provider_id="bad-provider", manifest_url=bad.manifest_url),
        ProviderConfig(provider_id="good-provider", manifest_url=good.manifest_url),
    ])
    report = run_crawl(config, store)

    statuses = {r.provider_id: r.status for r in report.results}
    assert statuses == {"bad-provider": "failed", "good-provider": "ok"}
    assert store.count_items("good-provider") == 1
    assert store.count_items("bad-provider") == 0


def test_disabled_providers_are_skipped(provider, store, settings):
    provider.publish([segment(1, upserts=[{"id": "a"}])])
    config = Config(settings=settings, providers=[
        ProviderConfig(provider_id=PROVIDER_ID,
                       manifest_url=provider.manifest_url, enabled=False),
    ])
    report = run_crawl(config, store)
    assert report.results == []


def test_segment_gap_stops_the_sequence(provider, store, make_config):
    """
    Segments are deltas, so v1 then v3 must not be applied as if contiguous.
    We take v1 and wait for v2 to appear.
    """
    provider.publish([
        segment(1, upserts=[{"id": "a"}]),
        segment(3, upserts=[{"id": "c"}]),
    ])
    report = run_crawl(make_config(provider), store)

    assert report.results[0].segments_applied == [1]
    assert store.get_item(PROVIDER_ID, "c") is None


# --------------------------------------------------------------- configuration

def test_config_is_loaded_from_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "crawler:\n"
        "  database_path: ./db/catalog.db\n"
        "  request_timeout_seconds: 7\n"
        "providers:\n"
        "  - id: alpha\n"
        "    manifest_url: https://alpha.example.com/manifest.json\n"
        "  - id: beta\n"
        "    manifest_url: https://beta.example.com/manifest.json\n"
        "    enabled: false\n"
    )
    config = load_config(path)

    assert config.settings.request_timeout_seconds == 7
    assert [p.provider_id for p in config.providers] == ["alpha", "beta"]
    assert config.providers[1].enabled is False
    assert config.settings.database_path.endswith("catalog.db")


def test_empty_provider_list_is_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("providers: []\n")
    with pytest.raises(ConfigError, match="non-empty list"):
        load_config(path)


def test_duplicate_provider_ids_are_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "providers:\n"
        "  - id: alpha\n    manifest_url: https://a.example.com/manifest.json\n"
        "  - id: alpha\n    manifest_url: https://b.example.com/manifest.json\n"
    )
    with pytest.raises(ConfigError, match="duplicated"):
        load_config(path)


def test_missing_config_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does-not-exist.yaml")


def test_download_size_cap_is_enforced(provider, store, settings):
    provider.publish([segment(1, upserts=[{"id": f"item-{i}"} for i in range(50)])])
    tiny = CrawlerSettings(
        database_path=settings.database_path,
        max_download_bytes=50,          # far smaller than the segment
        max_retries=1,
        retry_backoff_seconds=0.01,
    )
    config = Config(settings=tiny, providers=[
        ProviderConfig(provider_id=PROVIDER_ID, manifest_url=provider.manifest_url)])

    report = run_crawl(config, store)
    assert report.results[0].status == "failed"
    assert "limit" in report.results[0].error


def test_non_json_response_is_rejected(provider, store, make_config):
    provider.publish([segment(1, upserts=[{"id": "a"}])])
    (provider.root / "manifest.json").write_text("<html>404 Not Found</html>")

    report = run_crawl(make_config(provider), store)
    assert report.results[0].status == "failed"
    assert "not valid JSON" in report.results[0].error
