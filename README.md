# Decentralized Catalog Crawler

A configuration-driven crawler that discovers catalog data published as static JSON by independent providers, verifies it's authentic and untampered, and merges it into a single aggregated catalog.

The awkward part of the problem is that providers publish to plain static hosting (S3, a CDN) with no live API. So there's no authenticated endpoint and no TLS handshake with the provider that tells us the data is genuine — we're fetching files off whatever server they happen to use. Trust has to come from the data itself, and that constraint drives most of the design below.

## Table of contents

* [Quick start](#quick-start)
* [What the crawler does](#what-the-crawler-does)
* [Architecture](#architecture)
* [Security model](#security-model)
* [Storage design and merging](#storage-design-and-merging)
* [Resilience: what happens when it crashes](#resilience-what-happens-when-it-crashes)
* [Testing](#testing)
* [Configuration reference](#configuration-reference)
* [Trade-offs and what I'd change at scale](#trade-offs-and-what-id-change-at-scale)

## Quick start

Needs Python 3.9+. There's no database server, no Docker, nothing to install beyond three Python packages.

```bash
# 1. Create an isolated environment
python -m venv .venv

#    Windows (PowerShell):
.venv\\Scripts\\Activate.ps1
#    macOS / Linux:
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate the mock provider (real keypair, real signatures)
python mock\_provider/generate\_mock\_data.py

# 4. Crawl it
python main.py crawl --config config.yaml

# 5. Inspect the result
python main.py status --config config.yaml
python main.py list   --config config.yaml
```

Step 4 should print something like:

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
  \[OK]          acme-retail: applied v1, v2 -> 8 upserted, 1 removed
------------------------------------------------------------
  1 provider(s) processed, 0 failed.
```

Run it again and it reports `\[UP-TO-DATE]` without re-downloading anything.

### Run the tests

```bash
python -m pytest
```

47 tests, under a second, fully offline.

### Watch the security layer catch an attack

```bash
python scripts/demo\_tamper.py
```

Runs one honest crawl and three tampering attacks, and shows each attack being rejected with nothing written to the database.

### Crawl over real HTTP instead of local files

The default config reads the mock provider off disk so the project runs with no server. To exercise the same code path over the network:

```bash
# Terminal 1 - serve the static files, exactly like a CDN would
python -m http.server 8000 --directory mock\_provider/public

# Terminal 2
python main.py crawl --config config.http.yaml
```

## What the crawler does

A provider publishes three kinds of file. The `manifest.json` rarely changes and holds the provider's public key plus a pointer to their index — it's the root of trust. The `index.json` is rewritten on every publish and contains a signed, version-numbered list of the available segments, each with a SHA-256 digest. The `segment\_vN.json` files are append-only and hold the actual deltas: items to upsert and item IDs to remove.

For each configured provider the crawler fetches the manifest from the URL in the config and checks it names the provider we expected. It fetches the index and verifies its Ed25519 signature against the manifest's public key, then confirms the index version hasn't gone backwards relative to what we've already applied. From there it works out which segments are new (`version > last\_applied\_version`) and, in strict ascending order, fetches each one, checks its SHA-256 digest against the signed index, and applies it to storage inside a single transaction.

Nothing gets parsed, trusted, or stored until both cryptographic gates have passed.

## Architecture

Each module does one job and doesn't reach into the others' internals.

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
    │ URL ->   │   │ signature  │   │ SQLite,  │
    │ bytes    │   │ + digest   │   │ atomic   │
    └──────────┘   └────────────┘   └──────────┘
                          ^
                    ┌───────────┐
                    │  models   │  typed parsing; rejects malformed input at the door
                    └───────────┘
```

* `crawler/config.py` — loads and validates the YAML config, failing fast with a precise message.
* `crawler/fetcher.py` — turns a URL into bytes. Handles `http(s)://`, `file://` and local paths, with timeouts, bounded retries with exponential backoff, and a download size cap.
* `crawler/verifier.py` — Ed25519 signature verification and SHA-256 digest checks, written as pure functions with no I/O so they're easy to test exhaustively.
* `crawler/models.py` — typed dataclasses with validating constructors. Everything from the internet passes through here first.
* `crawler/storage.py` — SQLite persistence, transactions, and the merge logic.
* `crawler/crawler.py` — orchestration. Knows the order of operations and delegates the rest.
* `crawler/canonical.py` — deterministic JSON serialisation for signing.
* `crawler/errors.py` — a typed exception hierarchy so callers can tell transient failures apart from trust failures.

The payoff from this split: the orchestrator never touches a socket or writes SQL, so moving from SQLite to Postgres means rewriting `storage.py` and nothing else. The verifier does no I/O, so its tests are fast. And the fetcher's `file://` support is what lets the whole suite run offline against the same path production uses.

## Security model

### The chain of trust

We verify one signature per crawl no matter how many segments exist, because the signed index vouches for every segment by digest:

```
manifest.json ──contains──> PUBLIC KEY
                                │ verifies
                                v
                          index.json  (signed with the provider's PRIVATE key)
                                │ declares SHA-256 digest of each
                                v
                          segment\_v1.json, segment\_v2.json, ...
```

Public-key verification is expensive and hashing is nearly free, so signing the index and hashing the segments gives full coverage for the cost of a single signature check.

### Choice of primitives

I used **Ed25519** for signatures. It's deterministic — it doesn't depend on a good random number generator at signing time, which is where a number of ECDSA implementations have failed badly — and it's fast, with 32-byte keys and 64-byte signatures and no parameters to misconfigure. RSA would also work, but with larger keys and more ways to get it wrong.

Digests are **SHA-256**, stored as `sha256:<hex>` rather than bare hex. The prefix means the algorithm can be upgraded later without ambiguity, and it lets the crawler reject an attempt to downgrade to a weaker hash rather than silently accepting it.

### What it defends against

The interesting failure modes, and where each is stopped:

* A CDN is compromised and a segment file is edited → the digest no longer matches the signed index.
* The index is edited to match the forged segment → the signature stops verifying.
* An attacker signs a forged index with their own key → it doesn't verify against the manifest's public key.
* The signature is swapped in claiming a different key → the `key\_id` has to match the manifest.
* An old but validly-signed index is replayed to hide a recall → the monotonic version check rejects the rollback.
* Provider A's signed index is replayed as provider B's → the `provider\_id` in the payload has to match both the manifest and the config.
* One segment is substituted for another from the same provider → the segment's own declared version has to match what the index listed.
* A server returns an endless response to exhaust memory → the streaming download aborts past `max\_download\_bytes`.
* A broken hash algorithm is declared → only `sha256` is accepted.

Each of these has a test in `tests/test\_verification.py` named after the attack it simulates.

### Fail closed

Any verification failure aborts that provider immediately and writes nothing. There's no "log a warning and keep going" path, because a crawler that stores data it couldn't verify is worse than one that stores nothing — downstream consumers can't tell the two apart.

### What it doesn't protect against

Worth being upfront about the limits. A dishonest provider that signs bad data will produce a valid signature; cryptography proves origin, not truthfulness. The manifest itself isn't signed — it's the root of trust, and we trust it because its URL comes from our own config. In production that URL needs to be HTTPS with certificate validation, and ideally the expected `key\_id` would be pinned in the config so a swapped manifest is caught too. And if a provider's private key leaks, everything signed with it is trusted, so a real deployment needs key rotation, expiry, and revocation.

## Storage design and merging

### Why SQLite

The workload needs a few specific things. Writes have to be atomic across many rows — a segment is a batch of upserts and removals that must all land or none of them, and that one requirement rules out most of the simple options. It needs upsert-by-key as the core merge operation, and it needs to track per-provider progress durably, committed together with the data that progress describes. Updates should be cheap and incremental, so changing one item doesn't rewrite the whole catalog. And it should be runnable by a reviewer with a clone and nothing else.

I looked at the obvious candidates:

Plain JSON files on disk fall over on the first requirement. There are no transactions, so a crash mid-write corrupts the file, and I'd have to hand-roll atomicity with temp-file-plus-rename — which doesn't extend to updating two files together anyway. Every one-item change rewrites the whole catalog.

Postgres is the right answer at real scale: concurrent writers, replication, richer indexing, JSONB with GIN indexes for search. The only reason I didn't use it here is that making a reviewer stand up a server to run a take-home is a bad trade.

MongoDB's document model fits heterogeneous catalog items nicely and its upsert semantics map well, but it has the same operational cost, and multi-document transactions need a replica set.

Elasticsearch is the right *search* layer, and end-users searching across providers is the actual goal — but it's a poor system of record, with no real transactions and a reindex that needs a durable source. It belongs downstream of this database, not in place of it.

So: SQLite. Full ACID transactions, native `INSERT ... ON CONFLICT DO UPDATE`, a single portable file, and it ships inside Python so it adds no dependency. It handles millions of rows without complaint. And because `storage.py` exposes a deliberately narrow interface — `apply\_segment`, `get\_provider\_state`, `list\_items` — nothing else in the codebase knows SQL exists, so swapping in Postgres later is a contained change.

### Schema

```sql
CREATE TABLE catalog\_items (
    provider\_id    TEXT    NOT NULL,
    item\_id        TEXT    NOT NULL,
    payload        TEXT    NOT NULL,   -- the item's full JSON document
    source\_version INTEGER NOT NULL,   -- which segment last wrote this row
    updated\_at     TEXT    NOT NULL,
    PRIMARY KEY (provider\_id, item\_id)
);

CREATE TABLE provider\_state (
    provider\_id          TEXT PRIMARY KEY,
    last\_applied\_version INTEGER NOT NULL DEFAULT 0,
    last\_index\_version   INTEGER,
    last\_crawled\_at      TEXT,
    last\_status          TEXT
);

CREATE TABLE applied\_segments (
    provider\_id     TEXT    NOT NULL,
    segment\_version INTEGER NOT NULL,
    digest          TEXT    NOT NULL,
    upsert\_count    INTEGER NOT NULL,
    removal\_count   INTEGER NOT NULL,
    applied\_at      TEXT    NOT NULL,
    PRIMARY KEY (provider\_id, segment\_version)
);
```

A few things worth explaining. The primary key on `catalog\_items` is the composite `(provider\_id, item\_id)` because item IDs are only unique within a provider — two providers might both use `sku-1001` for completely different products. Keying on `item\_id` alone would let one provider overwrite or delete another's inventory, which is both a data bug and an attack; the composite key makes it impossible.

The item body is stored as a JSON document rather than exploded into columns. Providers publish heterogeneous catalogs — retail items and services won't share a column layout, and onboarding a new provider shouldn't need a schema migration. Promoting the identity fields to real columns keeps lookups indexed while leaving the body flexible. If specific fields need querying later, SQLite supports generated columns and expression indexes over JSON without a rewrite.

`applied\_segments` is an audit trail — it answers "when did we ingest this, and what digest did we verify?" long after the fact, and doubles as a second layer of idempotency protection.

### Merge semantics

Upserts use SQLite's native upsert:

```sql
INSERT INTO catalog\_items (provider\_id, item\_id, payload, source\_version, updated\_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(provider\_id, item\_id) DO UPDATE SET
    payload        = excluded.payload,
    source\_version = excluded.source\_version,
    updated\_at     = excluded.updated\_at;
```

Removals are a scoped delete. Deleting an ID that isn't there is a no-op rather than an error, because providers do legitimately republish removals and a harmless duplicate shouldn't fail an otherwise-valid segment.

Because segments are deltas, order matters: applying v2 before v1 lands you in a different, wrong end state. The crawler sorts by version and applies strictly in sequence. If the index has a gap — v1 and v3 but no v2 — it applies v1 and stops, and picks up the rest on a later run once v2 shows up, rather than skipping ahead and corrupting the merged view.

## Resilience: what happens when it crashes

The brief asks specifically about a crash halfway through downloading or saving a segment. Both are handled, and each has a test.

**Crashing while downloading** is the easy case, because nothing's been written yet. The crawler pulls the whole segment into memory, verifies its digest, and only then opens a transaction. A partial download just fails the digest check — a truncated file hashes to something else — the provider's progress marker is untouched, and the next run retries from the same point. There's no window where partially-downloaded bytes reach the database.

**Crashing while saving** is the case that actually matters, and it's handled by putting the data and the progress marker in the same transaction:

```python
with self.transaction() as cur:          # BEGIN IMMEDIATE
    ... all upserts ...
    ... all removals ...
    ... record the applied segment ...
    ... advance last\_applied\_version ...
                                          # COMMIT
```

Sharing a transaction means they share a fate. SQLite writes to a write-ahead log first and only marks the transaction committed once that log entry is durable, so at any instant the on-disk database reflects either the state before the segment or the state after it, never halfway. Kill the process mid-write and the next connection finds an uncommitted transaction and rolls it back during recovery.

The database runs with `journal\_mode=WAL` and `synchronous=FULL`, so every commit is fsynced. That costs some write throughput and buys the guarantee that a committed transaction survives an OS crash or power loss — which is exactly the guarantee the rest of this design leans on.

The invariant that makes restart trivial is that `last\_applied\_version` can never be ahead of, or behind, the data it describes. On the next run the crawler reads the marker and resumes from the following segment. No repair step, no reconciliation pass, no partial state to detect.

A few things follow from that. Re-running over already-processed data changes nothing, so it's safe to schedule aggressively or re-run after a failure without thinking about it. Segments commit one at a time, so if v1–v5 succeed and v6 is corrupt, v1–v5 stay applied and the next run retries only v6. Each provider crawls in its own try/except with its own transactions, so one provider serving garbage can't block the others. And because the transaction context manager catches `BaseException` rather than just `Exception`, a `Ctrl+C` rolls back cleanly instead of leaving a transaction dangling.

One thing I deliberately didn't handle: two crawler processes running concurrently against the same database would both attempt the same segments. `BEGIN IMMEDIATE` keeps that safe — one blocks, and the loser's work is idempotent anyway — but it's wasteful. A production deployment would add an advisory lock or a lease per provider. I'm calling it out rather than pretending it's solved, because it's a real gap, just not one worth fixing at this scale.

## Testing

```bash
python -m pytest              # all 47 tests
python -m pytest -v           # verbose
python -m pytest tests/test\_verification.py   # security tests only
```

Every test builds its own provider in a temp directory with a freshly-generated keypair and genuinely valid signatures — nothing is stubbed. They drive the same fetch → verify → store path a real crawl uses, just over `file://` URLs, so they run offline in under a second while still exercising the real cryptography.

* `tests/test\_verification.py` — 16 tests. Valid signatures accepted, every tampering scenario above rejected.
* `tests/test\_storage.py` — 14 tests. Merge semantics, provider isolation, and the atomicity guarantees, including deliberately crashing mid-transaction and asserting the database is untouched.
* `tests/test\_crawler.py` — 17 tests. End-to-end crawls, incremental publishes, resume-after-crash, failure isolation, config validation.

The one I'd point at first is `test\_crash\_midway\_through\_a\_transaction\_leaves\_no\_partial\_data`, since it proves the resilience claim above rather than just asserting it in prose.

## Configuration reference

No URL appears anywhere in the source — it all lives in the config file, chosen at runtime with `--config`.

```yaml
crawler:
  database\_path: ./data/catalog.db   # relative paths resolve against this file
  request\_timeout\_seconds: 10        # give up on a silent server
  max\_retries: 3                     # retry transient failures
  retry\_backoff\_seconds: 0.5         # 0.5s, 1s, 2s between attempts
  max\_download\_bytes: 10485760       # 10 MiB cap per file

providers:
  - id: acme-retail
    manifest\_url: ./mock\_provider/public/manifest.json
    enabled: true
```

Adding a provider is a config change with no code change. Setting `enabled: false` quarantines a misbehaving provider without deleting its history.

### CLI

* `python main.py crawl` — run the crawler.
* `python main.py status` — per-provider version, status, and last crawl time.
* `python main.py list` — dump the merged catalog as JSON (`--provider` to filter).
* `-v` / `--verbose` — debug logging.

Exit codes are meaningful so the crawler can be scheduled and monitored without parsing its output: `0` all providers succeeded, `1` at least one failed, `2` the config was invalid.

## Trade-offs and what I'd change at scale

A handful of things I chose deliberately for this exercise, with what production would want instead.

Segments are downloaded fully into memory. That's fine for deltas of a few megabytes and it keeps the verify-before-parse logic simple. At hundreds of megabytes I'd stream to a temp file and hash while streaming, then parse — still verifying before parsing either way, since parsing untrusted input is its own attack surface.

Providers are crawled sequentially, which is clear and correct but I/O-bound once there are hundreds of them. They're fully independent, so they parallelise cleanly with a worker pool — at which point Postgres beats SQLite for the concurrent writes.

The signature covers a re-serialised canonical payload (sorted keys, no whitespace). That's simple and keeps the mock files human-readable, which matters for a take-home. Production should use RFC 8785 (JSON Canonicalization Scheme), which pins down number formatting exactly, or a JWS-style layout where the payload travels as base64url of the exact original bytes so there's no re-serialisation at all. There's a note about this in `crawler/canonical.py`.

There's no key rotation or revocation. The `key\_id` field is in place so rotation can be added without a format change, but there's no expiry, no key history, and no revocation list. A real network needs all three.

There are no conditional requests. Adding `If-None-Match` / `If-Modified-Since` would let providers return `304 Not Modified` and save bandwidth on the common no-change case. Easy to add to the fetcher.

There's no search layer. The stated goal is end-users searching across providers; this database is the durable system of record, and a search index (Elasticsearch, or SQLite FTS5 for modest volumes) would be fed from it rather than replacing it.

And ordering assumes a single publisher per provider — segment versions are a plain increasing integer. Multiple independent publishers behind one provider would need a coordinated sequence or something like vector clocks.

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
├── mock\_provider/
│   ├── generate\_mock\_data.py      generates a real keypair and signs the files
│   └── public/                    the "CDN": manifest, index, segments
├── scripts/
│   └── demo\_tamper.py             live demonstration of tamper detection
└── tests/
    ├── conftest.py                fixtures that build signed providers
    ├── test\_verification.py       security tests
    ├── test\_storage.py            merge and atomicity tests
    └── test\_crawler.py            end-to-end tests
```

One note on the mock provider's private key: `generate\_mock\_data.py` writes `mock\_provider/private\_key.pem` so the mock data is reproducible, and it's excluded by `.gitignore` — a real provider's signing key would live in a KMS or HSM and never touch source control. The public key is committed inside `manifest.json`, which is where it belongs.

