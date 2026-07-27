# Decentralized Catalog Crawler

A crawler that finds catalog data published as static JSON by independent providers, checks the data is authentic and hasn't been tampered with, and merges it all into one catalog. It's driven entirely by a config file.

Providers publish to plain static hosting like S3 or a CDN, with no live API. So there's no authenticated endpoint or transport security to lean on to prove the data is genuine — the trust has to come from the data itself. That single constraint drove most of the design decisions here.

---

## Table of contents

- [Quick start](#quick-start)
- [What the crawler does](#what-the-crawler-does)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Storage design and merging](#storage-design-and-merging)
- [Resilience: what happens when it crashes](#resilience-what-happens-when-it-crashes)
- [Testing](#testing)
- [Configuration reference](#configuration-reference)
- [Trade-offs and what I would change at scale](#trade-offs-and-what-i-would-change-at-scale)

---

## Quick start

Requires Python 3.9 or newer. No database server, no Docker, nothing to install beyond three Python packages.

```bash
# 1. Create an isolated environment
python -m venv .venv

#    Windows (PowerShell) - if activation is blocked, first run:
#      Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
#    macOS / Linux:
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate the mock provider (real keypair, real signatures)
python mock_provider/generate_mock_data.py

# 4. Crawl it
python main.py crawl --config config.yaml

# 5. Inspect the result
python main.py status --config config.yaml
python main.py list   --config config.yaml
```
**Windows note:** if PowerShell blocks the activation script with an execution-policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once in that terminal, then activate again. It only affects the current session.

Expected output from step 4:

```
INFO     Crawling provider 'acme-retail'
INFO       signature OK - index v2, 2 segment(s) listed
INFO       fetching segment v1
INFO       digest OK for segment v1
INFO       committed segment v1 (5 upserted, 0 removed)
INFO       fetching segment v2
INFO       digest OK for segment v2
INFO       committed segment v2 (3 upserted, 1 removed)

Crawl summary
------------------------------------------------------------
  [OK]          acme-retail: applied v1, v2 -> 8 upserted, 1 removed
------------------------------------------------------------
  1 provider(s) processed, 0 failed.
```

Run it a second time and it reports `[UP-TO-DATE]` without re-downloading anything.

### Run the tests

```bash
python -m pytest
```

47 tests, under a second, entirely offline.

### See the security layer catch an attack

```bash
python scripts/demo_tamper.py
```

This runs four scenarios — one honest crawl and three different tampering attacks — and shows each attack being rejected with zero rows written.

### Crawl over real HTTP instead of local files

The default config reads the mock provider from disk so the project runs with no server. To prove the same code path works over the network:

```bash
The core promise of this project is the same code path works whether the data comes from a local file or a real CDN over HTTP.
This section shows the crawler pulling from an actual HTTP server (python -m http.server, which behaves just like a CDN) using a different config file, with zero code changes.
That's the proof that the `file://` vs `http://` handling in the fetcher is real, not a shortcut.

# Terminal 1 - serve the static files, exactly like a CDN would
python -m http.server 8000 --directory mock_provider/public

# Terminal 2
python main.py crawl --config config.http.yaml
```

---

## What the crawler does

A provider publishes three kinds of file:

| File | Changes | Purpose |
|---|---|---|
| `manifest.json` | Rarely | The provider's public key and a pointer to their index. The root of trust. |
| `index.json` | Every publish | A signed list of available segments, each with a SHA-256 digest, plus a version number. |
| `segment_vN.json` | Append-only | The actual deltas: items to upsert, item IDs to remove. |

For each configured provider, the crawler:

1. Fetches `manifest.json` from the URL in the config file and confirms it names the provider we expected.
2. Fetches `index.json` and **verifies its Ed25519 signature** against the manifest's public key.
3. Confirms the index version has not gone *backwards* relative to what we already applied.
4. Works out which segments are new (`version > last_applied_version`).
5. For each, in strict ascending order: fetch the bytes, **verify the SHA-256 digest** against the signed index, then apply it to storage inside a single transaction.

Nothing gets parsed, trusted, or stored until both crypto checks pass.

---

## Architecture

The code is split so that each module has one job and no knowledge of the others' internals.

```
config.yaml  ─────────────┐
                          v
                    ┌───────────┐
                    │  config   │  loads and validates YAML; no URL is hardcoded
                    └─────┬─────┘
                          v
                    ┌───────────┐
                    │  crawler  │  owns the SEQUENCE of a crawl and nothing else
                    └─────┬─────┘
          ┌───────────────┼───────────────┐
          v               v               v
    ┌──────────┐   ┌────────────┐   ┌──────────┐
    │ fetcher  │   │  verifier  │   │ storage  │
    │          │   │            │   │          │
    │ URL ->   │   │ signature  │   │ SQLite,  │
    │ bytes.   │   │ + digest   │   │ atomic   │
    │ Retries, │   │ checks.    │   │ segment  │
    │ timeouts,│   │ Pure       │   │ apply.   │
    │ size cap │   │ functions  │   │          │
    └──────────┘   └────────────┘   └──────────┘
                          ^
                    ┌───────────┐
                    │  models   │  typed parsing; rejects malformed input at the door
                    └───────────┘
```

| Module | Responsibility |
|---|---|
| `crawler/config.py` | Load and validate the YAML config. Fails fast with a precise message. |
| `crawler/fetcher.py` | Turn a URL into bytes. Handles `http(s)://`, `file://` and local paths. Timeouts, bounded retries with exponential backoff, download size cap. |
| `crawler/verifier.py` | Ed25519 signature verification and SHA-256 digest verification. Pure functions — no I/O, which makes them trivial to test exhaustively. |
| `crawler/models.py` | Typed dataclasses with validating constructors. Everything from the internet passes through here first. |
| `crawler/storage.py` | SQLite persistence. Owns transactions and the merge logic. |
| `crawler/crawler.py` | Orchestration only. Knows the order of operations, delegates everything else. |
| `crawler/canonical.py` | Deterministic JSON serialisation for signing. |
| `crawler/errors.py` | Typed exception hierarchy so callers can distinguish transient from trust failures. |

Why bother splitting it up like this? The orchestrator never touches a socket or writes SQL, so if you wanted to swap SQLite for Postgres you'd only rewrite one file. The verifier does no I/O at all, which makes it easy to test thoroughly. And because the fetcher handles file:// URLs, the whole test suite can run offline against the exact same code path production uses.

---

## Security model

### The chain of trust

We verify **one** signature per crawl regardless of how many segments exist, because the signed index vouches for every segment by digest:

```
manifest.json ──contains──> PUBLIC KEY
                                │
                                │ verifies
                                v
                          index.json  (signed with the provider's PRIVATE key)
                                │
                                │ declares SHA-256 digest of each
                                v
                          segment_v1.json, segment_v2.json, ...
```

Public-key operations are expensive and hashing is basically free, so signing the index and hashing the segments gets us full coverage for the price of a single signature check.

### Choice of primitives

**Ed25519** for signatures. It's deterministic, so it doesn't depend on a good random number generator at signing time — which is exactly where a lot of ECDSA implementations have blown up badly. It's also fast, the keys are small (32 bytes, 64-byte signatures), and there are no parameters to get wrong. RSA would work too, but with much bigger keys and more ways to misconfigure it.

**SHA-256** for digests. Standard, collision-resistant, universally available. Digests are stored as `sha256:<hex>` rather than bare hex so the algorithm can be upgraded later without ambiguity — and so an attacker cannot silently downgrade us to a broken hash, which the crawler explicitly rejects.

### Attacks this defends against

| Attack | Defence |
|---|---|
| CDN compromised, segment file edited | Digest mismatch against the signed index |
| Index edited to match the forged segment | Signature no longer verifies |
| Attacker signs a forged index with their own key | Signature does not verify against the manifest's public key |
| Signature swapped in claiming a different key | `key_id` in the signature must match the manifest |
| Old but validly signed index replayed to hide a recall | Monotonic version check rejects rollbacks |
| Provider A's signed index replayed as provider B's | `provider_id` in the payload must match the manifest and the config |
| Segment substituted for another from the same provider | Segment's own declared version must match what the index listed |
| Endless response to exhaust memory | Streaming download aborts past `max_download_bytes` |
| Broken hash algorithm declared | Only `sha256` is accepted |

All of these have tests in `tests/test_verification.py`, each named after the attack it simulates.

### Fail closed

Any verification failure stops that provider right there and writes nothing. There's no "log a warning and keep going" path on purpose. A crawler that stores data it couldn't verify is worse than one that stores nothing at all, since whatever's reading from it downstream has no way to tell the good data from the bad.

### What this does *not* protect against

Honest limitations, stated plainly:

- **A dishonest provider.** If they sign bad data, the signature is valid. Cryptography proves *origin*, not *truthfulness*.
- **A forged manifest.** The manifest is the root of trust and is not itself signed — we trust it because its URL comes from our own configuration. In production the manifest URL must be HTTPS with certificate validation, and ideally the expected `key_id` would be pinned in the config so a swapped manifest is rejected too.
- **Key compromise.** If a provider's private key leaks, everything signed with it is trusted. Real deployments need key rotation, an expiry on `key_id`, and a revocation mechanism.

---

## Storage design and merging

### The choice: SQLite

The assignment asks for a justification, so here is the reasoning rather than just the conclusion.

**What the workload actually needs:**

1. **Atomic multi-row writes.** A segment contains many upserts and removals that must all land or none of them. This is the single hardest requirement and it eliminates most simple options.
2. **Upsert by key.** "Insert this item, or overwrite it if it already exists" is the core merge operation.
3. **Durable progress tracking**, committed together with the data it describes.
4. **Cheap incremental updates.** Changing one item must not mean rewriting the whole catalog.
5. **Zero setup for a reviewer.** Someone evaluating this should be able to clone and run.

**How the options compare:**

| Option | Verdict |
|---|---|
| **Plain JSON files on disk** | Rejected. No transactions — a crash mid-write corrupts the file. Atomicity would have to be hand-rolled with temp-file-plus-rename, which does not extend to updating two files together. Rewrites the whole catalog for a one-item change. |
| **SQLite** | **Chosen.** Full ACID transactions. Native `INSERT ... ON CONFLICT DO UPDATE`. Single portable file. Ships inside Python, so it adds no dependency. Handles millions of rows comfortably. |
| **PostgreSQL** | Right answer at real scale — concurrent writers, replication, richer indexing, JSONB with GIN indexes for search. Rejected here only because requiring a reviewer to stand up a server to run a take-home is the wrong trade. |
| **MongoDB** | Document model fits heterogeneous catalog items nicely and its upsert semantics map well. Rejected for the same operational reason, plus multi-document transactions need a replica set. |
| **Elasticsearch** | The right *search* layer, and end-users searching across providers is the stated goal. But it is a poor system of record: no real transactions, and reindexing needs a durable source. It belongs *downstream* of this database, not instead of it. |

**The decisive point:** the interface in `storage.py` is deliberately narrow — `apply_segment`, `get_provider_state`, `list_items`. Nothing else in the codebase knows SQL exists. Migrating to Postgres means rewriting that one file. Choosing SQLite now is therefore a cheap decision to reverse, which is exactly the kind of decision worth making quickly.

### Schema

```sql
CREATE TABLE catalog_items (
    provider_id    TEXT    NOT NULL,
    item_id        TEXT    NOT NULL,
    payload        TEXT    NOT NULL,   -- the item's full JSON document
    source_version INTEGER NOT NULL,   -- which segment last wrote this row
    updated_at     TEXT    NOT NULL,
    PRIMARY KEY (provider_id, item_id)
);

CREATE TABLE provider_state (
    provider_id          TEXT PRIMARY KEY,
    last_applied_version INTEGER NOT NULL DEFAULT 0,
    last_index_version   INTEGER,
    last_crawled_at      TEXT,
    last_status          TEXT
);

CREATE TABLE applied_segments (
    provider_id     TEXT    NOT NULL,
    segment_version INTEGER NOT NULL,
    digest          TEXT    NOT NULL,
    upsert_count    INTEGER NOT NULL,
    removal_count   INTEGER NOT NULL,
    applied_at      TEXT    NOT NULL,
    PRIMARY KEY (provider_id, segment_version)
);
```

Three design decisions worth calling out:

**The composite primary key `(provider_id, item_id)`.** Item IDs are only unique *within* a provider. Two providers may both use `sku-1001` for entirely different products. Keying on `item_id` alone would let one provider silently overwrite or delete another's inventory — a data-integrity bug that also happens to be an attack. The composite key makes that structurally impossible.

**The item body stored as a JSON document.** Providers publish heterogeneous catalogs — retail items and services will not share a column layout, and a new provider must not require a schema migration. Storing the body as JSON with the identity fields promoted to real columns keeps ingestion flexible while keeping lookups indexed. If specific fields later need querying, SQLite supports generated columns and expression indexes over JSON without a rewrite.

**`applied_segments` as an audit trail.** Answers "when did we ingest this, and what digest did we verify?" long after the fact, and provides a second layer of idempotency protection.

### Merge semantics

Upserts use SQLite's native upsert:

```sql
INSERT INTO catalog_items (provider_id, item_id, payload, source_version, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(provider_id, item_id) DO UPDATE SET
    payload        = excluded.payload,
    source_version = excluded.source_version,
    updated_at     = excluded.updated_at;
```

Removals are a scoped delete. Deleting an ID that does not exist is treated as a **no-op, not an error** — providers legitimately republish removals, and a harmless duplicate must not fail an otherwise valid segment.

**Segments are deltas, so the order they're applied in matters a lot. Apply v2 before v1 and you get a different, wrong result. The crawler sorts by version and applies them strictly in order. If there's a gap in the index (say v1 and v3 but no v2), it applies v1 and stops, then picks up the rest on a later run once v2 shows up — better than skipping ahead and quietly corrupting the merged catalog.

---

## Resilience: what happens when it crashes

What happens if the crawler dies halfway through downloading or saving a segment? Both cases are covered, and both have tests.

### Crash while downloading

Nothing has been written yet — the crawler downloads the entire segment into memory, verifies its digest, and only then opens a transaction. A partial download simply fails the digest check, because a truncated file hashes to something different. The provider's progress marker is untouched, and the next run retries from the same point.

There is no window in which partially downloaded bytes could reach the database.

### Crash while saving

This is the case that actually matters, and it's handled by writing the data and the progress marker in the same transaction**:

```python
with self.transaction() as cur:          # BEGIN IMMEDIATE
    ... all upserts ...
    ... all removals ...
    ... record the applied segment ...
    ... advance last_applied_version ...
                                          # COMMIT
```

Since they're in the same transaction, they succeed or fail together. SQLite writes to a write-ahead log first and only counts the transaction as committed once that log entry is safely on disk, so at any given moment the database is either in its state before the segment or after it, never stuck in between. If the process gets killed mid-write, the next connection notices the uncommitted transaction and rolls it back automatically.

The database is configured with `journal_mode=WAL` and `synchronous=FULL`, meaning every commit is fsynced. That costs some write throughput and buys the guarantee that a committed transaction survives an OS crash or power loss — which is precisely the guarantee this design leans on.

### The key invariant

> `last_applied_version` can never be ahead of, or behind, the data it describes.

That is what makes restart trivial. On the next run the crawler reads the marker and resumes from the following segment. There is no repair step, no reconciliation pass, no partial state to detect.

### Consequences that follow from it

- **Idempotent.** Re-running over already-processed data changes nothing. Safe to schedule aggressively or re-run after a failure without thinking about it.
- **Progress is never lost.** Segments commit one at a time, so if v1..v5 succeed and v6 is corrupt, v1..v5 stay applied and the next run retries only v6.
- **Failure isolation.** Each provider crawls in its own try/except with its own transactions. One provider serving garbage cannot block the others.
- **Ctrl+C is safe.** The transaction context manager catches `BaseException`, not just `Exception`, so a `KeyboardInterrupt` rolls back rather than leaving a transaction dangling.

### What is deliberately *not* handled

If you ran two crawler processes against the same database at once, they'd both go after the same segments. BEGIN IMMEDIATE keeps this safe — one just blocks, and the loser's work is idempotent anyway — but it's wasteful. In production I'd add an advisory lock or a lease per provider. I'm flagging it rather than pretending it isn't there, because it's a real gap; it's just not worth solving at this scale.

---

## Testing

```bash
python -m pytest              # all 47 tests
python -m pytest -v           # verbose
python -m pytest tests/test_verification.py   # security tests only
```

Every test builds its own provider in a temporary directory with a freshly generated keypair and genuinely valid signatures. Nothing is stubbed. The tests drive the same fetch → verify → store path a production crawl uses, just over `file://` URLs — so they run offline in under a second while still exercising the real cryptography.

| File | Covers |
|---|---|
| `tests/test_verification.py` | 16 tests. Valid signatures accepted; every tampering scenario in the attack table rejected. |
| `tests/test_storage.py` | 14 tests. Merge semantics, provider isolation, and the atomicity guarantees — including deliberately crashing mid-transaction and asserting the database is untouched. |
| `tests/test_crawler.py` | 17 tests. End-to-end crawls, incremental publishes, resume-after-crash, failure isolation, config validation. |

The most important test is `test_crash_midway_through_a_transaction_leaves_no_partial_data`, which actually proves the resilience claim above instead of just asserting it.

---

## Configuration reference

No URL appears anywhere in the source. Everything lives in the config file, chosen at runtime with `--config`.

```yaml
crawler:
  database_path: ./data/catalog.db   # relative paths resolve against this file
  request_timeout_seconds: 10        # give up on a silent server
  max_retries: 3                     # retry transient failures
  retry_backoff_seconds: 0.5         # 0.5s, 1s, 2s between attempts
  max_download_bytes: 10485760       # 10 MiB cap per file

providers:
  - id: acme-retail
    manifest_url: ./mock_provider/public/manifest.json
    enabled: true
```

Adding a provider is a config change with no code change. `enabled: false` quarantines a misbehaving provider without deleting its history.

### CLI

| Command | Purpose |
|---|---|
| `python main.py crawl` | Run the crawler |
| `python main.py status` | Per-provider version, status and last crawl time |
| `python main.py list` | Dump the merged catalog as JSON (`--provider` to filter) |
| `-v` / `--verbose` | Debug logging |

Exit codes are meaningful so the crawler can be scheduled and monitored without parsing its output: `0` all providers succeeded, `1` at least one failed, `2` the configuration was invalid.

---

## Trade-offs and what I would change at scale

Things I chose deliberately for this exercise, and what I'd do differently in production:

**Segments are downloaded fully into memory.** Fine for catalog deltas of a few megabytes and it keeps the verify-before-parse logic simple. At hundreds of megabytes I would stream to a temp file, hash while streaming, and only then parse — verifying before parsing either way, since parsing untrusted input is itself an attack surface.

**Providers are crawled sequentially.** Clear, easy to reason about, and correct. With hundreds of providers this becomes I/O-bound and wasteful; since providers are fully independent, they parallelise cleanly with a worker pool. Postgres would then be a better fit than SQLite for concurrent writers.

**The signature covers a re-serialised payload.** Canonical JSON (sorted keys, no whitespace) is simple and keeps the mock files human-readable, which matters for a reviewable take-home. Production should use RFC 8785 (JSON Canonicalization Scheme), which pins down number formatting precisely, or a JWS-style layout where the payload travels as base64url of the *exact original bytes* so no re-serialisation ever happens. This is noted in `crawler/canonical.py`.

**No key rotation or revocation.** The `key_id` field is in place so rotation can be added without a format change, but there is no expiry, no key history, and no revocation list. A real network needs all three.

**No conditional requests.** Adding `If-None-Match` / `If-Modified-Since` would let providers return `304 Not Modified` and save bandwidth on the common no-change case. Straightforward to add to the fetcher.

**No search layer.** The goal is end-users searching across providers. This database is the durable system of record; a search index (Elasticsearch, or SQLite FTS5 for modest volumes) would be fed from it rather than replacing it.

**Ordering assumes one publisher per provider.** Segment versions are a simple increasing integer. If a provider had multiple independent publishers, they would need a coordinated sequence or a different ordering scheme such as vector clocks.

---

## Project layout

```
decentralized-catalog-crawler/
├── main.py                        CLI entrypoint
├── config.yaml                    default config (local files, no server)
├── config.http.yaml               config for crawling over real HTTP
├── requirements.txt
├── pytest.ini
├── crawler/
│   ├── config.py                  YAML loading and validation
│   ├── fetcher.py                 URL -> bytes; retries, timeouts, size cap
│   ├── verifier.py                signature and digest verification
│   ├── models.py                  typed, validating parsers
│   ├── storage.py                 SQLite persistence and merging
│   ├── crawler.py                 orchestration
│   ├── canonical.py               deterministic JSON for signing
│   └── errors.py                  typed exceptions
├── mock_provider/
│   ├── generate_mock_data.py      generates a real keypair and signs the files
│   └── public/                    the "CDN": manifest, index, segments
├── scripts/
│   └── demo_tamper.py             live demonstration of tamper detection
└── tests/
    ├── conftest.py                fixtures that build signed providers
    ├── test_verification.py       security tests
    ├── test_storage.py            merge and atomicity tests
    └── test_crawler.py            end-to-end tests
```

**A note on the mock provider's private key.** `generate_mock_data.py` writes `mock_provider/private_key.pem` so the mock data is reproducible. It is excluded by `.gitignore`, because a real provider's signing key would live in a KMS or HSM and never touch source control. The *public* key is committed inside `manifest.json`, which is exactly where it belongs.
