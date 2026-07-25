"""
Typed representations of the documents a provider publishes.

Everything arriving from the internet is untrusted, so each ``from_dict``
classmethod acts as a gate: it checks that required fields exist and have
sensible types, and raises VerificationError otherwise. Once an object of one
of these classes exists, the rest of the code can rely on its shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .errors import VerificationError

SUPPORTED_SIGNATURE_ALGORITHMS = {"ed25519"}
SUPPORTED_DIGEST_ALGORITHMS = {"sha256"}


def _require(d: Dict[str, Any], key: str, expected_type: type, context: str) -> Any:
    if key not in d:
        raise VerificationError(f"{context}: missing required field '{key}'")
    value = d[key]
    # bool is a subclass of int in Python; reject it where an int is expected.
    if expected_type is int and isinstance(value, bool):
        raise VerificationError(f"{context}: field '{key}' must be an integer")
    if not isinstance(value, expected_type):
        raise VerificationError(
            f"{context}: field '{key}' must be {expected_type.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


@dataclass(frozen=True)
class PublicKey:
    """The provider's Ed25519 verification key, as advertised in the manifest."""

    key_id: str
    algorithm: str
    encoding: str
    value: str

    @classmethod
    def from_dict(cls, d: Any) -> "PublicKey":
        ctx = "manifest.public_key"
        if not isinstance(d, dict):
            raise VerificationError(f"{ctx}: must be an object")
        algorithm = _require(d, "algorithm", str, ctx).lower()
        if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise VerificationError(f"{ctx}: unsupported algorithm '{algorithm}'")
        encoding = _require(d, "encoding", str, ctx).lower()
        if encoding != "base64":
            raise VerificationError(f"{ctx}: unsupported key encoding '{encoding}'")
        return cls(
            key_id=_require(d, "key_id", str, ctx),
            algorithm=algorithm,
            encoding=encoding,
            value=_require(d, "value", str, ctx),
        )


@dataclass(frozen=True)
class Manifest:
    """manifest.json - the provider's stable 'business card'."""

    provider_id: str
    name: str
    index_url: str
    public_key: PublicKey

    @classmethod
    def from_dict(cls, d: Any) -> "Manifest":
        ctx = "manifest"
        if not isinstance(d, dict):
            raise VerificationError(f"{ctx}: must be a JSON object")
        return cls(
            provider_id=_require(d, "provider_id", str, ctx),
            name=d.get("name", ""),
            index_url=_require(d, "index_url", str, ctx),
            public_key=PublicKey.from_dict(d.get("public_key")),
        )


@dataclass(frozen=True)
class SegmentRef:
    """One entry in the index's segment list: where a segment lives + its digest."""

    version: int
    url: str
    digest: str          # "sha256:<hex>"
    size_bytes: Optional[int] = None

    @property
    def digest_algorithm(self) -> str:
        return self.digest.split(":", 1)[0].lower()

    @property
    def digest_hex(self) -> str:
        return self.digest.split(":", 1)[1].lower()

    @classmethod
    def from_dict(cls, d: Any, position: int) -> "SegmentRef":
        ctx = f"index.payload.segments[{position}]"
        if not isinstance(d, dict):
            raise VerificationError(f"{ctx}: must be an object")

        version = _require(d, "version", int, ctx)
        if version < 1:
            raise VerificationError(f"{ctx}: version must be >= 1")

        digest = _require(d, "digest", str, ctx)
        if ":" not in digest:
            raise VerificationError(
                f"{ctx}: digest must be '<algorithm>:<hex>', got '{digest}'"
            )
        algorithm, hex_part = digest.split(":", 1)
        if algorithm.lower() not in SUPPORTED_DIGEST_ALGORITHMS:
            raise VerificationError(f"{ctx}: unsupported digest algorithm '{algorithm}'")
        if len(hex_part) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_part):
            raise VerificationError(f"{ctx}: digest is not a valid SHA-256 hex string")

        size_bytes = d.get("size_bytes")
        if size_bytes is not None and (not isinstance(size_bytes, int) or size_bytes < 0):
            raise VerificationError(f"{ctx}: size_bytes must be a non-negative integer")

        return cls(
            version=version,
            url=_require(d, "url", str, ctx),
            digest=digest,
            size_bytes=size_bytes,
        )


@dataclass(frozen=True)
class IndexPayload:
    """The signed body of index.json."""

    provider_id: str
    version: int
    key_id: str
    segments: List[SegmentRef]
    published_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Any) -> "IndexPayload":
        ctx = "index.payload"
        if not isinstance(d, dict):
            raise VerificationError(f"{ctx}: must be an object")

        version = _require(d, "version", int, ctx)
        if version < 1:
            raise VerificationError(f"{ctx}: version must be >= 1")

        raw_segments = _require(d, "segments", list, ctx)
        segments = [SegmentRef.from_dict(s, i) for i, s in enumerate(raw_segments)]

        seen = set()
        for seg in segments:
            if seg.version in seen:
                raise VerificationError(
                    f"{ctx}: duplicate segment version {seg.version}"
                )
            seen.add(seg.version)

        segments.sort(key=lambda s: s.version)

        return cls(
            provider_id=_require(d, "provider_id", str, ctx),
            version=version,
            key_id=_require(d, "key_id", str, ctx),
            segments=segments,
            published_at=d.get("published_at"),
        )


@dataclass(frozen=True)
class Segment:
    """A data segment: items to insert/update, and item IDs to delete."""

    provider_id: str
    version: int
    upserts: List[Dict[str, Any]] = field(default_factory=list)
    removals: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Any, expected_version: int) -> "Segment":
        ctx = f"segment_v{expected_version}"
        if not isinstance(d, dict):
            raise VerificationError(f"{ctx}: must be a JSON object")

        version = _require(d, "version", int, ctx)
        if version != expected_version:
            raise VerificationError(
                f"{ctx}: declares version {version} but the index listed it as "
                f"version {expected_version}"
            )

        upserts = _require(d, "upserts", list, ctx) if "upserts" in d else []
        for i, item in enumerate(upserts):
            if not isinstance(item, dict):
                raise VerificationError(f"{ctx}: upserts[{i}] must be an object")
            if not isinstance(item.get("id"), str) or not item.get("id"):
                raise VerificationError(f"{ctx}: upserts[{i}] needs a non-empty string 'id'")

        removals = _require(d, "removals", list, ctx) if "removals" in d else []
        for i, item_id in enumerate(removals):
            if not isinstance(item_id, str) or not item_id:
                raise VerificationError(f"{ctx}: removals[{i}] must be a non-empty string")

        return cls(
            provider_id=_require(d, "provider_id", str, ctx),
            version=version,
            upserts=upserts,
            removals=removals,
        )
