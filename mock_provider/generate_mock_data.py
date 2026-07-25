#!/usr/bin/env python3
"""
Mock provider generator.

Simulates what a real provider's publishing pipeline would do:

  1. Generate an Ed25519 keypair. The PRIVATE key stays with the provider and
     is what makes signatures; the PUBLIC key is published in the manifest so
     anyone can verify those signatures.
  2. Write the data segments.
  3. Compute the SHA-256 digest of each segment file's exact bytes.
  4. Build the index payload listing those digests.
  5. SIGN the canonical bytes of that payload with the private key.
  6. Write manifest.json, index.json and the segments into ./public/

The output in mock_provider/public/ is static JSON - exactly what would sit in
an S3 bucket or behind a CDN. The crawler has no idea it is talking to a mock.

    python mock_provider/generate_mock_data.py
    python mock_provider/generate_mock_data.py --base-url http://127.0.0.1:8000

IMPORTANT: the private key written to mock_provider/private_key.pem exists only
so this repository is self-contained and reproducible. A real provider's
private key would never be committed to source control - it would live in a
KMS or HSM. The .gitignore excludes it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
PUBLIC_DIR = HERE / "public"
PRIVATE_KEY_PATH = HERE / "private_key.pem"

PROVIDER_ID = "acme-retail"
PROVIDER_NAME = "Acme Retail Pvt Ltd"
KEY_ID = "acme-key-2026-01"


def canonical_json_bytes(obj) -> bytes:
    """Must match crawler/canonical.py exactly, or signatures will not verify."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_or_create_private_key() -> Ed25519PrivateKey:
    """Reuse the existing key if present, so regenerating does not invalidate it."""
    if PRIVATE_KEY_PATH.exists():
        return serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(), password=None
        )

    key = Ed25519PrivateKey.generate()
    PRIVATE_KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


def public_key_base64(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------- content

def segment_one() -> dict:
    """The provider's initial publish: five items added."""
    return {
        "provider_id": PROVIDER_ID,
        "version": 1,
        "published_at": now(),
        "upserts": [
            {"id": "sku-1001", "name": "Stainless Steel Water Bottle 1L",
             "category": "kitchenware", "price": 899, "currency": "INR", "in_stock": True},
            {"id": "sku-1002", "name": "Cotton Bath Towel (Pack of 2)",
             "category": "home-textiles", "price": 1249, "currency": "INR", "in_stock": True},
            {"id": "sku-1003", "name": "Ceramic Coffee Mug 350ml",
             "category": "kitchenware", "price": 349, "currency": "INR", "in_stock": True},
            {"id": "sku-1004", "name": "LED Desk Lamp with USB Port",
             "category": "lighting", "price": 1599, "currency": "INR", "in_stock": False},
            {"id": "sku-1005", "name": "Bamboo Cutting Board Large",
             "category": "kitchenware", "price": 749, "currency": "INR", "in_stock": True},
        ],
        "removals": [],
    }


def segment_two() -> dict:
    """
    A later publish that exercises every merge case:
      - sku-1003 is UPDATED (price change, now out of stock)  -> upsert-as-update
      - sku-1006 and sku-1007 are NEW                          -> upsert-as-insert
      - sku-1004 is DELETED                                    -> removal
      - sku-9999 is deleted but never existed                  -> must not error
    """
    return {
        "provider_id": PROVIDER_ID,
        "version": 2,
        "published_at": now(),
        "upserts": [
            {"id": "sku-1003", "name": "Ceramic Coffee Mug 350ml",
             "category": "kitchenware", "price": 399, "currency": "INR", "in_stock": False},
            {"id": "sku-1006", "name": "Wall Clock Minimalist 30cm",
             "category": "home-decor", "price": 1199, "currency": "INR", "in_stock": True},
            {"id": "sku-1007", "name": "Insulated Lunch Box 2 Tier",
             "category": "kitchenware", "price": 1449, "currency": "INR", "in_stock": True},
        ],
        "removals": ["sku-1004", "sku-9999"],
    }


# ----------------------------------------------------------------------- build

def build(base_url: str) -> None:
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    private_key = load_or_create_private_key()

    segments = [segment_one(), segment_two()]
    segment_refs = []

    for segment in segments:
        filename = f"segment_v{segment['version']}.json"
        # Write first, then hash the bytes that were actually written. Hashing
        # the file rather than the in-memory object guarantees the digest
        # describes exactly what a crawler will download.
        raw = json.dumps(segment, indent=2, ensure_ascii=False).encode("utf-8")
        (PUBLIC_DIR / filename).write_bytes(raw)

        segment_refs.append({
            "version": segment["version"],
            "url": f"{base_url.rstrip('/')}/{filename}" if base_url else filename,
            "digest": sha256_digest(raw),
            "size_bytes": len(raw),
        })

    index_payload = {
        "provider_id": PROVIDER_ID,
        "version": len(segments),
        "key_id": KEY_ID,
        "published_at": now(),
        "segments": segment_refs,
    }

    signature = private_key.sign(canonical_json_bytes(index_payload))

    index_document = {
        "payload": index_payload,
        "signature": {
            "algorithm": "ed25519",
            "key_id": KEY_ID,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
    (PUBLIC_DIR / "index.json").write_bytes(
        json.dumps(index_document, indent=2, ensure_ascii=False).encode("utf-8")
    )

    manifest = {
        "provider_id": PROVIDER_ID,
        "name": PROVIDER_NAME,
        "index_url": f"{base_url.rstrip('/')}/index.json" if base_url else "index.json",
        "public_key": {
            "key_id": KEY_ID,
            "algorithm": "ed25519",
            "encoding": "base64",
            "value": public_key_base64(private_key),
        },
        "created_at": now(),
    }
    (PUBLIC_DIR / "manifest.json").write_bytes(
        json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    )

    print(f"Mock provider written to {PUBLIC_DIR}")
    print(f"  provider_id : {PROVIDER_ID}")
    print(f"  key_id      : {KEY_ID}")
    print(f"  index       : v{index_payload['version']} with {len(segment_refs)} segment(s)")
    for ref in segment_refs:
        print(f"    v{ref['version']}: {ref['digest']}")
    print("\nURLs in the files are "
          + ("relative (resolved against the manifest URL)." if not base_url
             else f"absolute, based at {base_url}"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate signed mock provider files.")
    parser.add_argument(
        "--base-url",
        default="",
        help="Absolute base URL to embed in the files. Leave empty to use relative "
             "URLs, which work for both file:// and http:// crawling.",
    )
    args = parser.parse_args()
    build(args.base_url)


if __name__ == "__main__":
    main()
