"""
Trust and integrity layer.

THE CHAIN OF TRUST
------------------
We never trust a segment because it "looks fine". Trust flows down a chain,
and every link is checked:

    manifest.json  ->  contains the provider's PUBLIC KEY
         |
         v
    index.json     ->  SIGNED with the provider's PRIVATE KEY.
         |             Verifying that signature with the public key proves the
         |             index genuinely came from the provider and was not
         |             altered in transit.
         v
    segments       ->  the verified index lists a SHA-256 DIGEST for each one.
                       Recomputing the digest of the downloaded bytes and
                       comparing proves the segment is exactly the file the
                       provider intended to publish.

The elegant part: we verify exactly ONE signature per crawl, no matter how many
segments there are. The signed index vouches for all of them by digest. Digests
are cheap; public-key operations are not.

WHAT THIS DOES AND DOES NOT PROTECT AGAINST
-------------------------------------------
It protects against tampering by anyone who does not hold the private key -
a compromised CDN, a hijacked S3 bucket, an attacker on the network path.

It does NOT protect against a provider that is itself dishonest: if they sign
bad data, the signature is valid. Nor does it protect us if we fetch the
manifest itself from an impostor, which is why the manifest URL comes from our
own trusted configuration and should be HTTPS in production. Pinning the
expected key_id in config would harden this further.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json_bytes
from .errors import VerificationError
from .models import IndexPayload, Manifest, PublicKey

# Ed25519 keys are always exactly 32 bytes and signatures exactly 64 bytes.
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64


def compute_digest(data: bytes, algorithm: str = "sha256") -> str:
    """Return ``'<algorithm>:<hex>'`` for ``data``."""
    algorithm = algorithm.lower()
    if algorithm != "sha256":
        raise VerificationError(f"Unsupported digest algorithm '{algorithm}'")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def verify_digest(data: bytes, expected_digest: str, context: str) -> None:
    """
    Recompute the digest of ``data`` and compare it to ``expected_digest``.

    Uses ``hmac.compare_digest`` semantics via a constant-time comparison to
    avoid leaking information through timing. That matters far less for a
    public digest than for a secret, but constant-time comparison of security
    values is a habit worth keeping.
    """
    algorithm, _, expected_hex = expected_digest.partition(":")
    actual = compute_digest(data, algorithm)
    _, _, actual_hex = actual.partition(":")

    if not hmac.compare_digest(actual_hex.lower(), expected_hex.lower()):
        raise VerificationError(
            f"{context}: digest mismatch. The index declared {expected_digest} "
            f"but the downloaded bytes hash to {actual}. The file has been "
            f"modified, truncated, or replaced - refusing to process it."
        )


def load_public_key(public_key: PublicKey) -> Ed25519PublicKey:
    """Turn the base64 key material from the manifest into a usable key object."""
    try:
        raw = base64.b64decode(public_key.value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(
            f"manifest.public_key.value is not valid base64: {exc}"
        ) from exc

    if len(raw) != ED25519_PUBLIC_KEY_BYTES:
        raise VerificationError(
            f"manifest.public_key.value decodes to {len(raw)} bytes, "
            f"expected {ED25519_PUBLIC_KEY_BYTES} for Ed25519"
        )

    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:  # pragma: no cover - defensive
        raise VerificationError(f"Could not load Ed25519 public key: {exc}") from exc


def verify_index(
    index_document: Any,
    manifest: Manifest,
    last_applied_version: Optional[int] = None,
) -> IndexPayload:
    """
    Verify a parsed index.json against the provider's manifest.

    Performs, in order:
      1. structural checks on the envelope
      2. algorithm and key_id checks (the signature must claim the key we hold)
      3. the Ed25519 signature check over the canonical payload bytes
      4. provider identity check (index payload must name the same provider)
      5. monotonic version check (an index may never move the catalog backwards)

    Returns the validated payload. Raises VerificationError on any failure.
    """
    if not isinstance(index_document, dict):
        raise VerificationError("index: top-level value must be a JSON object")

    raw_payload = index_document.get("payload")
    if not isinstance(raw_payload, dict):
        raise VerificationError("index: missing 'payload' object")

    signature_block = index_document.get("signature")
    if not isinstance(signature_block, dict):
        raise VerificationError("index: missing 'signature' object")

    algorithm = str(signature_block.get("algorithm", "")).lower()
    if algorithm != manifest.public_key.algorithm:
        raise VerificationError(
            f"index.signature.algorithm is '{algorithm}' but the manifest "
            f"advertises '{manifest.public_key.algorithm}'"
        )

    # Refuse a signature that claims a different key than the one we hold. This
    # blocks an attacker who swaps in a signature made with their own key.
    signature_key_id = signature_block.get("key_id")
    if signature_key_id is not None and signature_key_id != manifest.public_key.key_id:
        raise VerificationError(
            f"index.signature.key_id '{signature_key_id}' does not match the "
            f"manifest key_id '{manifest.public_key.key_id}'"
        )

    signature_value = signature_block.get("value")
    if not isinstance(signature_value, str):
        raise VerificationError("index.signature.value must be a base64 string")

    try:
        signature_bytes = base64.b64decode(signature_value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(f"index.signature.value is not valid base64: {exc}") from exc

    if len(signature_bytes) != ED25519_SIGNATURE_BYTES:
        raise VerificationError(
            f"index.signature.value decodes to {len(signature_bytes)} bytes, "
            f"expected {ED25519_SIGNATURE_BYTES} for Ed25519"
        )

    # --- the actual cryptographic check -----------------------------------
    key = load_public_key(manifest.public_key)
    signed_bytes = canonical_json_bytes(raw_payload)
    try:
        key.verify(signature_bytes, signed_bytes)
    except InvalidSignature as exc:
        raise VerificationError(
            "index: SIGNATURE VERIFICATION FAILED. Either the file was modified "
            "after signing, or it was signed by someone other than the provider. "
            "Refusing to process this provider."
        ) from exc

    # --- post-signature semantic checks -----------------------------------
    payload = IndexPayload.from_dict(raw_payload)

    if payload.key_id != manifest.public_key.key_id:
        raise VerificationError(
            f"index.payload.key_id '{payload.key_id}' does not match the "
            f"manifest key_id '{manifest.public_key.key_id}'"
        )

    if payload.provider_id != manifest.provider_id:
        raise VerificationError(
            f"index.payload.provider_id '{payload.provider_id}' does not match "
            f"the manifest provider_id '{manifest.provider_id}'. A validly "
            f"signed index from one provider must not be replayed against another."
        )

    if last_applied_version is not None and payload.version < last_applied_version:
        raise VerificationError(
            f"index.payload.version {payload.version} is older than the "
            f"version {last_applied_version} we have already applied. This is a "
            f"rollback: an attacker may be serving a stale but validly signed "
            f"index to hide newer updates. Refusing."
        )

    return payload


def verify_manifest(manifest_document: Any, expected_provider_id: str) -> Manifest:
    """
    Parse a manifest and confirm it belongs to the provider we configured.

    The manifest is not itself signed - it is the root of trust, and we trust it
    because its URL came from our own configuration file (and, in production,
    because it is served over HTTPS with a valid certificate).
    """
    manifest = Manifest.from_dict(manifest_document)
    if manifest.provider_id != expected_provider_id:
        raise VerificationError(
            f"manifest.provider_id is '{manifest.provider_id}' but the "
            f"configuration expected '{expected_provider_id}'"
        )
    return manifest
