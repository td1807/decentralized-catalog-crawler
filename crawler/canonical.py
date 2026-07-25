"""
Canonical JSON serialisation.

THE PROBLEM THIS SOLVES
-----------------------
A digital signature is computed over a sequence of *bytes*, not over an
abstract "object". These two JSON documents mean exactly the same thing to a
program:

    {"version": 2, "id": "acme"}
    {
      "id"      : "acme",
      "version" : 2
    }

...but they are completely different byte strings, so they produce completely
different signatures. If the provider signs one form and we re-serialise into
the other form before verifying, verification fails even though nothing was
tampered with.

The fix is a "canonicalisation" rule that both sides agree on: given the same
logical object, always produce the same bytes. Our rule is:

  * keys sorted alphabetically
  * no insignificant whitespace  (separators are "," and ":")
  * UTF-8 output, non-ASCII characters left as-is rather than \\u-escaped

PRODUCTION NOTE (worth mentioning in an interview)
--------------------------------------------------
Re-serialising a parsed object is convenient but subtly risky in general: JSON
numbers such as 1.0 / 1E0 / 1 all parse to the same Python float and would be
re-emitted identically, so a hostile publisher could in principle craft two
different byte strings that canonicalise the same way. Real systems solve this
with either
  (a) RFC 8785 (JSON Canonicalization Scheme), which specifies number
      formatting precisely, or
  (b) a JWS-style layout where the payload is transported as base64url of the
      *exact original bytes*, so no re-serialisation is ever needed.
We use the simple sorted-key form here because it keeps the mock files
human-readable, which matters for a reviewable take-home.
"""

from __future__ import annotations

import json
from typing import Any


def canonical_json_bytes(obj: Any) -> bytes:
    """Serialise ``obj`` to the deterministic byte form used for signatures."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
