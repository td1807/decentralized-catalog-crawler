"""
Security tests.

These are the most important tests in the repository. A crawler that merges
data correctly but accepts forged data is worse than no crawler at all, so
every one of these asserts that BAD input is REJECTED.

Each test names the attack it simulates.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import KEY_ID, PROVIDER_ID, MockProvider, segment
from crawler.errors import VerificationError
from crawler.models import Manifest
from crawler.verifier import compute_digest, verify_digest, verify_index, verify_manifest


def _manifest_of(provider: MockProvider) -> Manifest:
    return Manifest.from_dict(json.loads((provider.root / "manifest.json").read_text()))


# --------------------------------------------------------------- happy path

def test_valid_signature_is_accepted(provider):
    provider.publish([segment(1, upserts=[{"id": "a", "name": "A"}])])
    payload = verify_index(provider.read_index(), _manifest_of(provider))
    assert payload.version == 1
    assert payload.provider_id == PROVIDER_ID


def test_digest_matches_for_untouched_segment(provider):
    provider.publish([segment(1, upserts=[{"id": "a", "name": "A"}])])
    index = provider.read_index()
    ref = index["payload"]["segments"][0]
    raw = (provider.root / "segment_v1.json").read_bytes()
    verify_digest(raw, ref["digest"], "segment v1")  # must not raise


# ------------------------------------------------- attack: index was edited

def test_editing_the_signed_payload_breaks_the_signature(provider):
    """
    Attacker with write access to the CDN edits the index to point at their own
    malicious segment. They cannot re-sign it without the private key, so the
    signature no longer matches the payload bytes.
    """
    provider.publish([segment(1, upserts=[{"id": "a", "name": "A"}])])
    index = provider.read_index()
    index["payload"]["segments"][0]["url"] = "https://evil.example.com/segment.json"
    provider.write_index_raw(index)

    with pytest.raises(VerificationError, match="SIGNATURE VERIFICATION FAILED"):
        verify_index(provider.read_index(), _manifest_of(provider))


def test_bumping_the_version_breaks_the_signature(provider):
    provider.publish([segment(1)])
    index = provider.read_index()
    index["payload"]["version"] = 99
    provider.write_index_raw(index)

    with pytest.raises(VerificationError, match="SIGNATURE VERIFICATION FAILED"):
        verify_index(provider.read_index(), _manifest_of(provider))


# ------------------------------------------- attack: signed with a wrong key

def test_index_signed_by_a_different_key_is_rejected(provider, tmp_path):
    """
    Attacker generates their OWN keypair and signs a perfectly well-formed
    index with it. The signature is internally valid - but it does not verify
    against the public key the real provider published.
    """
    provider.publish([segment(1)])
    genuine_manifest = _manifest_of(provider)

    impostor = MockProvider(tmp_path / "impostor", provider_id=PROVIDER_ID,
                            private_key=Ed25519PrivateKey.generate())
    impostor.publish([segment(1)])

    with pytest.raises(VerificationError, match="SIGNATURE VERIFICATION FAILED"):
        verify_index(impostor.read_index(), genuine_manifest)


def test_signature_claiming_an_unknown_key_id_is_rejected(provider):
    provider.publish([segment(1)])
    index = provider.read_index()
    index["signature"]["key_id"] = "some-other-key"
    provider.write_index_raw(index)

    with pytest.raises(VerificationError, match="does not match the manifest key_id"):
        verify_index(provider.read_index(), _manifest_of(provider))


# ------------------------------------------- attack: segment content swapped

def test_modified_segment_fails_the_digest_check(provider):
    """
    The index is genuine and its signature verifies, but the segment file
    itself was swapped after publication. SHA-256 catches it.
    """
    provider.publish([segment(1, upserts=[{"id": "a", "name": "A", "price": 100}])])
    index = provider.read_index()
    expected = index["payload"]["segments"][0]["digest"]

    provider.tamper_segment(1, lambda d: d["upserts"][0].update({"price": 1}))
    tampered = (provider.root / "segment_v1.json").read_bytes()

    with pytest.raises(VerificationError, match="digest mismatch"):
        verify_digest(tampered, expected, "segment v1")


def test_single_byte_change_changes_the_digest(provider):
    """A hash is only useful if tiny changes are visible. Demonstrate that."""
    a = compute_digest(b'{"price": 100}')
    b = compute_digest(b'{"price": 101}')
    assert a != b
    assert len(a.split(":")[1]) == 64


# ------------------------------------------------- attack: version rollback

def test_rollback_to_an_older_index_is_rejected(provider):
    """
    Attacker replays an OLD, validly signed index to hide a recall or a price
    correction. The signature is genuine, so only the monotonic version check
    catches this.
    """
    provider.publish([segment(1), segment(2)])
    manifest = _manifest_of(provider)

    with pytest.raises(VerificationError, match="rollback"):
        verify_index(provider.read_index(), manifest, last_applied_version=5)


def test_same_version_is_allowed(provider):
    """Re-serving the current index is normal, not an attack."""
    provider.publish([segment(1), segment(2)])
    payload = verify_index(provider.read_index(), _manifest_of(provider),
                           last_applied_version=2)
    assert payload.version == 2


# ------------------------------------ attack: cross-provider index replay

def test_index_from_another_provider_is_rejected(tmp_path):
    """
    A validly signed index belonging to provider B must not be accepted as
    provider A's, even though its signature is real.
    """
    other = MockProvider(tmp_path / "other", provider_id="other-provider")
    other.publish([segment(1, provider_id="other-provider")])

    manifest = Manifest.from_dict({
        "provider_id": "other-provider",
        "index_url": "index.json",
        "public_key": json.loads((other.root / "manifest.json").read_text())["public_key"],
    })
    payload = verify_index(other.read_index(), manifest)
    assert payload.provider_id == "other-provider"

    # Now claim the same document belongs to a different provider id.
    payload_dict = other.read_index()["payload"]
    payload_dict["provider_id"] = PROVIDER_ID
    other.resign_index(payload_dict)

    with pytest.raises(VerificationError, match="does not match the manifest provider_id"):
        verify_index(other.read_index(), manifest)


def test_manifest_provider_id_must_match_config(provider):
    provider.publish([segment(1)])
    document = json.loads((provider.root / "manifest.json").read_text())

    with pytest.raises(VerificationError, match="configuration expected"):
        verify_manifest(document, expected_provider_id="somebody-else")


# ----------------------------------------------------- malformed input

def test_missing_signature_block_is_rejected(provider):
    provider.publish([segment(1)])
    index = provider.read_index()
    del index["signature"]
    provider.write_index_raw(index)

    with pytest.raises(VerificationError, match="missing 'signature'"):
        verify_index(provider.read_index(), _manifest_of(provider))


def test_signature_of_wrong_length_is_rejected(provider):
    provider.publish([segment(1)])
    index = provider.read_index()
    index["signature"]["value"] = base64.b64encode(b"too short").decode("ascii")
    provider.write_index_raw(index)

    with pytest.raises(VerificationError, match="expected 64 for Ed25519"):
        verify_index(provider.read_index(), _manifest_of(provider))


def test_non_base64_signature_is_rejected(provider):
    provider.publish([segment(1)])
    index = provider.read_index()
    index["signature"]["value"] = "!!!not base64!!!"
    provider.write_index_raw(index)

    with pytest.raises(VerificationError, match="not valid base64"):
        verify_index(provider.read_index(), _manifest_of(provider))


def test_unsupported_digest_algorithm_is_rejected(provider):
    """
    Prevents an algorithm-downgrade attack, where an attacker declares a broken
    hash such as MD5 that they can find a collision for.
    """
    provider.publish([segment(1)])
    payload = provider.read_index()["payload"]
    payload["segments"][0]["digest"] = "md5:" + "0" * 32
    provider.resign_index(payload)

    with pytest.raises(VerificationError, match="unsupported digest algorithm"):
        verify_index(provider.read_index(), _manifest_of(provider))
