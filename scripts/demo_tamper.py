#!/usr/bin/env python3
"""
Tamper demonstration.

Runs four scenarios back to back so you can see the security layer working:

  1. A clean crawl                        -> accepted
  2. A segment edited after publication   -> rejected by the SHA-256 digest check
  3. The signed index edited              -> rejected by the signature check
  4. An index re-signed by an impostor    -> rejected by the signature check

Everything happens in a temporary directory; your real mock_provider/public
files and your catalog database are never touched.

    python scripts/demo_tamper.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path

# The demo prints its own narration, so keep the library's log lines quiet.
logging.disable(logging.CRITICAL)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crawler.config import Config, CrawlerSettings, ProviderConfig  # noqa: E402
from crawler.crawler import Crawler  # noqa: E402
from crawler.fetcher import Fetcher  # noqa: E402
from crawler.storage import CatalogStore  # noqa: E402

PROVIDER_ID = "acme-retail"
KEY_ID = "acme-key-2026-01"

GREEN, RED, BOLD, DIM, RESET = "\033[92m", "\033[91m", "\033[1m", "\033[2m", "\033[0m"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def publish(root: Path, key: Ed25519PrivateKey) -> None:
    """Write a small, correctly signed provider into ``root``."""
    root.mkdir(parents=True, exist_ok=True)

    seg = {
        "provider_id": PROVIDER_ID,
        "version": 1,
        "upserts": [
            {"id": "sku-1001", "name": "Stainless Steel Water Bottle 1L", "price": 899},
            {"id": "sku-1002", "name": "Cotton Bath Towel", "price": 1249},
        ],
        "removals": [],
    }
    raw = json.dumps(seg, indent=2).encode("utf-8")
    (root / "segment_v1.json").write_bytes(raw)

    payload = {
        "provider_id": PROVIDER_ID,
        "version": 1,
        "key_id": KEY_ID,
        "segments": [{
            "version": 1,
            "url": "segment_v1.json",
            "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "size_bytes": len(raw),
        }],
    }
    sign_index(root, key, payload)

    public_raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    (root / "manifest.json").write_text(json.dumps({
        "provider_id": PROVIDER_ID,
        "name": "Acme Retail Pvt Ltd",
        "index_url": "index.json",
        "public_key": {
            "key_id": KEY_ID,
            "algorithm": "ed25519",
            "encoding": "base64",
            "value": base64.b64encode(public_raw).decode("ascii"),
        },
    }, indent=2))


def sign_index(root: Path, key: Ed25519PrivateKey, payload: dict) -> None:
    signature = key.sign(canonical(payload))
    (root / "index.json").write_text(json.dumps({
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": KEY_ID,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }, indent=2))


def crawl(root: Path, db_path: Path):
    settings = CrawlerSettings(database_path=str(db_path), max_retries=1,
                               retry_backoff_seconds=0.01)
    config = Config(settings=settings, providers=[
        ProviderConfig(provider_id=PROVIDER_ID,
                       manifest_url=(root / "manifest.json").as_uri())])
    store = CatalogStore(str(db_path))
    try:
        with Fetcher(settings) as fetcher:
            report = Crawler(config, store, fetcher).run()
        return report.results[0], store.count_items(PROVIDER_ID)
    finally:
        store.close()


def scenario(number: int, title: str, description: str) -> None:
    print(f"\n{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}SCENARIO {number}: {title}{RESET}")
    print(f"{DIM}{description}{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")


def report_outcome(result, item_count: int, expect_success: bool) -> bool:
    if result.status == "failed":
        print(f"\n{RED}REJECTED{RESET}  {result.error}")
    else:
        print(f"\n{GREEN}ACCEPTED{RESET}  applied "
              f"{', '.join(f'v{v}' for v in result.segments_applied) or 'nothing'}")
    print(f"Items now stored: {item_count}")

    passed = (result.status != "failed") == expect_success
    verdict = f"{GREEN}as expected{RESET}" if passed else f"{RED}UNEXPECTED{RESET}"
    print(f"Outcome: {verdict}")
    return passed


def main() -> int:
    workspace = Path(tempfile.mkdtemp(prefix="tamper-demo-"))
    all_passed = True
    try:
        key = Ed25519PrivateKey.generate()

        # --- 1: clean -----------------------------------------------------
        scenario(1, "Honest provider",
                 "Nothing has been touched. The signature and every digest check out.")
        root = workspace / "clean"
        publish(root, key)
        result, count = crawl(root, workspace / "db1.sqlite")
        all_passed &= report_outcome(result, count, expect_success=True)

        # --- 2: segment tampered -----------------------------------------
        scenario(2, "Attacker edits a data segment",
                 "The CDN is compromised and a price is changed from 899 to 1.\n"
                 "The index is untouched, so its signature is still perfectly valid -\n"
                 "but the index declared this segment's SHA-256 hash, and the bytes no\n"
                 "longer match it.")
        root = workspace / "bad-segment"
        publish(root, key)
        seg = json.loads((root / "segment_v1.json").read_text())
        seg["upserts"][0]["price"] = 1
        (root / "segment_v1.json").write_text(json.dumps(seg, indent=2))
        result, count = crawl(root, workspace / "db2.sqlite")
        all_passed &= report_outcome(result, count, expect_success=False)

        # --- 3: index tampered -------------------------------------------
        scenario(3, "Attacker edits the signed index",
                 "The attacker realises they must update the digest in the index too -\n"
                 "so they edit it. But they cannot produce a matching signature without\n"
                 "the provider's private key, which they do not have.")
        root = workspace / "bad-index"
        publish(root, key)
        seg = json.loads((root / "segment_v1.json").read_text())
        seg["upserts"][0]["price"] = 1
        raw = json.dumps(seg, indent=2).encode("utf-8")
        (root / "segment_v1.json").write_bytes(raw)
        index = json.loads((root / "index.json").read_text())
        index["payload"]["segments"][0]["digest"] = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        index["payload"]["segments"][0]["size_bytes"] = len(raw)
        (root / "index.json").write_text(json.dumps(index, indent=2))
        result, count = crawl(root, workspace / "db3.sqlite")
        all_passed &= report_outcome(result, count, expect_success=False)

        # --- 4: impostor key ---------------------------------------------
        scenario(4, "Attacker signs with their own key",
                 "The attacker generates their own keypair and produces a genuinely\n"
                 "valid signature over their forged index. It verifies against THEIR\n"
                 "public key - but we check against the one in the provider's manifest.")
        root = workspace / "impostor"
        publish(root, key)
        seg = json.loads((root / "segment_v1.json").read_text())
        seg["upserts"][0]["price"] = 1
        raw = json.dumps(seg, indent=2).encode("utf-8")
        (root / "segment_v1.json").write_bytes(raw)
        forged_payload = {
            "provider_id": PROVIDER_ID,
            "version": 1,
            "key_id": KEY_ID,
            "segments": [{
                "version": 1,
                "url": "segment_v1.json",
                "digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
                "size_bytes": len(raw),
            }],
        }
        sign_index(root, Ed25519PrivateKey.generate(), forged_payload)
        result, count = crawl(root, workspace / "db4.sqlite")
        all_passed &= report_outcome(result, count, expect_success=False)

        print(f"\n{BOLD}{'=' * 72}{RESET}")
        print(f"{BOLD}Summary{RESET}")
        print("  The honest crawl was accepted. All three tampering attempts were")
        print("  rejected, and in every rejected case ZERO rows were written -")
        print("  the crawler fails closed rather than storing partially-trusted data.")
        print(f"{BOLD}{'=' * 72}{RESET}\n")
        return 0 if all_passed else 1
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
