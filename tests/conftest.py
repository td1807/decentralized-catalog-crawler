"""
Shared test fixtures.

Every test builds its own provider from scratch in a temporary directory, with
a freshly generated keypair and genuinely valid signatures. Nothing is stubbed
or mocked out - the tests exercise the same fetch -> verify -> store path that
a production crawl would, just over ``file://`` URLs instead of HTTPS. That
means the tests run offline, in under a second, and still prove the real
cryptography works.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crawler.config import Config, CrawlerSettings, ProviderConfig  # noqa: E402
from crawler.storage import CatalogStore  # noqa: E402

PROVIDER_ID = "test-provider"
KEY_ID = "test-key-01"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_of(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


class MockProvider:
    """Writes a signed provider into a directory and lets tests tamper with it."""

    def __init__(self, root: Path, provider_id: str = PROVIDER_ID,
                 private_key: Ed25519PrivateKey | None = None):
        self.root = root
        self.provider_id = provider_id
        self.private_key = private_key or Ed25519PrivateKey.generate()
        self.root.mkdir(parents=True, exist_ok=True)

    # -- publishing ------------------------------------------------------

    def publish(self, segments: List[Dict[str, Any]], key_id: str = KEY_ID) -> None:
        """Write segments, then a correctly signed index and manifest."""
        refs = []
        for segment in segments:
            name = f"segment_v{segment['version']}.json"
            raw = json.dumps(segment, indent=2).encode("utf-8")
            (self.root / name).write_bytes(raw)
            refs.append({
                "version": segment["version"],
                "url": name,
                "digest": sha256_of(raw),
                "size_bytes": len(raw),
            })

        payload = {
            "provider_id": self.provider_id,
            "version": max(s["version"] for s in segments),
            "key_id": key_id,
            "segments": refs,
        }
        self._write_index(payload, key_id)
        self._write_manifest(key_id)

    def _write_index(self, payload: Dict[str, Any], key_id: str) -> None:
        signature = self.private_key.sign(canonical(payload))
        document = {
            "payload": payload,
            "signature": {
                "algorithm": "ed25519",
                "key_id": key_id,
                "value": base64.b64encode(signature).decode("ascii"),
            },
        }
        (self.root / "index.json").write_text(json.dumps(document, indent=2))

    def _write_manifest(self, key_id: str) -> None:
        raw_public = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        manifest = {
            "provider_id": self.provider_id,
            "name": "Test Provider",
            "index_url": "index.json",
            "public_key": {
                "key_id": key_id,
                "algorithm": "ed25519",
                "encoding": "base64",
                "value": base64.b64encode(raw_public).decode("ascii"),
            },
        }
        (self.root / "manifest.json").write_text(json.dumps(manifest, indent=2))

    # -- tampering helpers ------------------------------------------------

    def read_index(self) -> Dict[str, Any]:
        return json.loads((self.root / "index.json").read_text())

    def write_index_raw(self, document: Dict[str, Any]) -> None:
        """Write an index WITHOUT re-signing - used to simulate tampering."""
        (self.root / "index.json").write_text(json.dumps(document, indent=2))

    def resign_index(self, payload: Dict[str, Any], key_id: str = KEY_ID) -> None:
        self._write_index(payload, key_id)

    def tamper_segment(self, version: int, mutate) -> None:
        """Edit a segment file on disk after the index was signed."""
        path = self.root / f"segment_v{version}.json"
        document = json.loads(path.read_text())
        mutate(document)
        path.write_text(json.dumps(document, indent=2))

    @property
    def manifest_url(self) -> str:
        return (self.root / "manifest.json").as_uri()


# ------------------------------------------------------------------ fixtures

def segment(version: int, upserts=None, removals=None,
            provider_id: str = PROVIDER_ID) -> Dict[str, Any]:
    return {
        "provider_id": provider_id,
        "version": version,
        "upserts": upserts or [],
        "removals": removals or [],
    }


@pytest.fixture
def settings(tmp_path) -> CrawlerSettings:
    return CrawlerSettings(
        database_path=str(tmp_path / "catalog.db"),
        request_timeout_seconds=5.0,
        max_retries=2,
        retry_backoff_seconds=0.01,
        max_download_bytes=1024 * 1024,
    )


@pytest.fixture
def store(settings) -> CatalogStore:
    s = CatalogStore(settings.database_path)
    yield s
    s.close()


@pytest.fixture
def provider(tmp_path) -> MockProvider:
    return MockProvider(tmp_path / "provider")


@pytest.fixture
def make_config(settings):
    def _make(provider_obj: MockProvider, provider_id: str = PROVIDER_ID) -> Config:
        return Config(
            settings=settings,
            providers=[ProviderConfig(provider_id=provider_id,
                                      manifest_url=provider_obj.manifest_url)],
        )
    return _make
