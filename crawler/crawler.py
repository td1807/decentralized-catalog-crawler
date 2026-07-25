"""
Orchestration.

This module owns the *sequence* of a crawl and nothing else. It does not know
how to open a socket, how Ed25519 works, or what SQL looks like - it delegates
each of those to fetcher.py, verifier.py and storage.py respectively. Keeping
the orchestration free of implementation detail is what makes each piece
independently testable and independently replaceable (swap SQLite for Postgres
and this file does not change at all).

THE SEQUENCE, PER PROVIDER
--------------------------
  1. Fetch manifest.json          (URL comes from config, never hardcoded)
  2. Check it names the provider we expected
  3. Fetch index.json
  4. VERIFY THE SIGNATURE against the manifest's public key   <-- trust gate 1
  5. Check the index version has not gone backwards
  6. Work out which segments are new (version > last_applied_version)
  7. For each new segment, in ascending version order:
        a. fetch the bytes
        b. VERIFY ITS SHA-256 DIGEST against the signed index  <-- trust gate 2
        c. apply it to storage inside a single transaction
  8. Report

ORDERING MATTERS. Segments are deltas, so applying v2 before v1 would produce a
different (wrong) end state. We sort by version and apply strictly in sequence,
and we stop at the first gap rather than skipping ahead.

FAILURE ISOLATION. One bad provider must not stop the others, so each provider
is crawled inside its own try/except and its own set of transactions.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urljoin

from .config import Config, ProviderConfig
from .errors import CrawlerError, FetchError, StorageError, VerificationError
from .fetcher import Fetcher
from .models import Manifest, Segment, SegmentRef
from .storage import CatalogStore
from .verifier import verify_digest, verify_index, verify_manifest

logger = logging.getLogger(__name__)


@dataclass
class ProviderResult:
    """What happened for a single provider during this run."""

    provider_id: str
    status: str = "ok"            # ok | up-to-date | failed
    index_version: Optional[int] = None
    segments_applied: List[int] = field(default_factory=list)
    items_upserted: int = 0
    items_removed: int = 0
    error: Optional[str] = None

    def summary_line(self) -> str:
        if self.status == "failed":
            return f"  [FAILED]      {self.provider_id}: {self.error}"
        if self.status == "up-to-date":
            return f"  [UP-TO-DATE]  {self.provider_id} (index v{self.index_version})"
        versions = ", ".join(f"v{v}" for v in self.segments_applied)
        return (
            f"  [OK]          {self.provider_id}: applied {versions} -> "
            f"{self.items_upserted} upserted, {self.items_removed} removed"
        )


@dataclass
class CrawlReport:
    results: List[ProviderResult] = field(default_factory=list)

    @property
    def failed(self) -> List[ProviderResult]:
        return [r for r in self.results if r.status == "failed"]

    def render(self) -> str:
        lines = ["", "Crawl summary", "-" * 60]
        lines.extend(r.summary_line() for r in self.results)
        lines.append("-" * 60)
        lines.append(
            f"  {len(self.results)} provider(s) processed, {len(self.failed)} failed."
        )
        return "\n".join(lines)


class Crawler:
    """Crawls every enabled provider in the supplied configuration."""

    def __init__(self, config: Config, store: CatalogStore, fetcher: Fetcher):
        self._config = config
        self._store = store
        self._fetcher = fetcher

    # ------------------------------------------------------------------ public

    def run(self) -> CrawlReport:
        report = CrawlReport()
        for provider in self._config.providers:
            if not provider.enabled:
                logger.info("Skipping disabled provider '%s'", provider.provider_id)
                continue
            report.results.append(self._crawl_provider(provider))
        return report

    # ----------------------------------------------------------------- private

    def _crawl_provider(self, provider: ProviderConfig) -> ProviderResult:
        result = ProviderResult(provider_id=provider.provider_id)
        logger.info("Crawling provider '%s'", provider.provider_id)

        try:
            manifest = self._load_manifest(provider)
            index_url = urljoin(provider.manifest_url, manifest.index_url)

            state = self._store.get_provider_state(provider.provider_id)
            index_document = self._fetch_json(index_url, "index.json")

            payload = verify_index(
                index_document,
                manifest,
                last_applied_version=state.last_applied_version,
            )
            result.index_version = payload.version
            logger.info(
                "  signature OK - index v%s, %d segment(s) listed",
                payload.version,
                len(payload.segments),
            )

            pending = self._select_pending_segments(payload.segments, state.last_applied_version)
            if not pending:
                result.status = "up-to-date"
                self._store.record_crawl_result(
                    provider.provider_id, "up-to-date", payload.version
                )
                logger.info("  already up to date at v%s", state.last_applied_version)
                return result

            for ref in pending:
                counts = self._apply_segment(provider, index_url, ref, payload.version)
                result.segments_applied.append(ref.version)
                result.items_upserted += counts["upserted"]
                result.items_removed += counts["removed"]

        except (FetchError, VerificationError, StorageError, CrawlerError) as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.error("  %s", exc)
            # Best-effort bookkeeping; never let it mask the original error.
            try:
                self._store.record_crawl_result(
                    provider.provider_id, "failed", result.index_version
                )
            except StorageError:
                logger.debug("Could not record failure state", exc_info=True)

        return result

    def _load_manifest(self, provider: ProviderConfig) -> Manifest:
        document = self._fetch_json(provider.manifest_url, "manifest.json")
        return verify_manifest(document, provider.provider_id)

    def _fetch_json(self, url: str, what: str) -> object:
        raw = self._fetcher.fetch(url)
        try:
            return json.loads(raw.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise VerificationError(f"{what} at {url} is not valid UTF-8: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise VerificationError(f"{what} at {url} is not valid JSON: {exc}") from exc

    @staticmethod
    def _select_pending_segments(
        segments: List[SegmentRef], last_applied_version: int
    ) -> List[SegmentRef]:
        """
        Return the segments we still need, in strict ascending order.

        Segments are deltas, so a missing version in the middle means we cannot
        safely continue past it - applying v4 without v3 would silently corrupt
        the merged view. We therefore stop at the first gap and pick the rest up
        on a later run, once the provider publishes it.
        """
        pending: List[SegmentRef] = []
        expected = last_applied_version + 1
        for ref in segments:  # already sorted by IndexPayload.from_dict
            if ref.version < expected:
                continue
            if ref.version != expected:
                logger.warning(
                    "  gap in segment sequence: expected v%s, index jumps to v%s. "
                    "Stopping here; will resume when the missing segment appears.",
                    expected,
                    ref.version,
                )
                break
            pending.append(ref)
            expected += 1
        return pending

    def _apply_segment(
        self,
        provider: ProviderConfig,
        index_url: str,
        ref: SegmentRef,
        index_version: int,
    ) -> dict:
        segment_url = urljoin(index_url, ref.url)
        logger.info("  fetching segment v%s", ref.version)

        raw = self._fetcher.fetch(segment_url)

        # TRUST GATE 2: nothing is parsed or stored until the bytes we received
        # hash to exactly what the signed index promised.
        verify_digest(raw, ref.digest, f"segment v{ref.version}")
        logger.info("  digest OK for segment v%s", ref.version)

        if ref.size_bytes is not None and len(raw) != ref.size_bytes:
            raise VerificationError(
                f"segment v{ref.version}: index declared {ref.size_bytes} bytes "
                f"but received {len(raw)}"
            )

        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VerificationError(f"segment v{ref.version} is not valid JSON: {exc}") from exc

        segment = Segment.from_dict(document, expected_version=ref.version)
        if segment.provider_id != provider.provider_id:
            raise VerificationError(
                f"segment v{ref.version} claims provider '{segment.provider_id}' "
                f"but belongs to '{provider.provider_id}'"
            )

        counts = self._store.apply_segment(
            provider_id=provider.provider_id,
            segment=segment,
            digest=ref.digest,
            index_version=index_version,
        )
        logger.info(
            "  committed segment v%s (%d upserted, %d removed)",
            ref.version,
            counts["upserted"],
            counts["removed"],
        )
        return counts
