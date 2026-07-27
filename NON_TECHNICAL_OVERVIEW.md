# Understanding This Project — No Coding Background Required



This program is an automated inspector for a marketplace with no central authority. 

Independent sellers each publish their own inventory online; the program visits each one, checks a cryptographic "wax seal" and "barcode" to prove nothing was forged or altered, and only then merges the verified data into one master ledger. If anything fails the check, that seller's update is thrown out — nothing broken ever gets saved.

\---

## The Analogy

Picture a farmers' market with independent stalls — Seafood stall, grocery stores, and others. There's no market manager tracking everyone's stock centrally. Each vendor posts their own inventory list on their own website, updated whenever it changes.



You want one search page where a shopper can look across *every* vendor at once. Something has to visit each vendor's page, read their latest list, and merge it into a single master ledger — without ever trusting a forged or tampered list. That "something" is this program.



|In the story...|In the actual system...|
|-|-|
|A vendor's stall|A data provider (e.g. a retailer)|
|The stall's signboard|`manifest.json` — publishes the vendor's public key|
|The sealed inventory summary|`index.json` — a signed list of updates, each with a fingerprint|
|A delivery batch|A "segment" — the actual items to add or remove|
|A wax seal on the summary|A digital (Ed25519) signature|
|A barcode on each batch|A SHA-256 digital fingerprint|
|The market's master ledger|The local database the program builds|
|The inspector doing rounds|This crawler program|



## Why Trust Is the Hard Part



These vendor pages are just plain files on ordinary web hosting — nothing about the hosting itself guarantees they're genuine. Anyone who tampered with that hosting, or intercepted the connection, could slip in a fake list: prices that don't exist, phantom stock, deleted items that were never actually gone.

So the inspector never takes a downloaded file at face value. Everything must prove itself before it's trusted.



## Two Checkpoints, No Exceptions



**Checkpoint 1 — the seal.**
Each vendor seals their sealed inventory summary with a private stamp only they hold. The inspector checks that stamp against the vendor's publicly known seal pattern. Mismatch → the whole file is rejected, unread.

**Checkpoint 2 — the barcode.**
The sealed summary doesn't carry the actual changes — it carries a fingerprint for each delivery batch. When the inspector downloads a batch, it recomputes the fingerprint. If even one item was swapped in transit, the fingerprint won't match, and that batch is discarded.

```
   vendor's signboard                sealed summary               delivery batch
  ┌───────────────────┐      ┌────────────────────────┐      ┌──────────────────┐
  │   public seal      │─────▶│  ✔ seal verified here   │─────▶│ ✔ fingerprint     │
  │   pattern          │      │  lists batch versions   │      │   checked here    │
  └───────────────────┘      │  + a fingerprint each    │      └──────────────────┘
                              └────────────────────────┘               │
                                                                        ▼
                                                              only now: merged into
                                                                the master ledger
```

Nothing is parsed, trusted, or saved until *both* checkpoints pass.



## Order Is Not Optional



Vendors publish incremental updates — "batch #1 adds five items," "batch #2 removes one, adds three." Applying #2 before #1 produces a ledger state that never really existed. If a batch goes missing, the inspector stops exactly there and waits for it on the next visit, rather than guessing and silently corrupting everything downstream.



## Nothing Is Ever Half-Saved



The riskiest moment is the actual save. If the computer loses power mid-write, is the ledger left in a broken, half-updated state? No — "save the items" and "mark this batch as complete" are treated as one inseparable action. Either both happen, or neither does. A crash simply means: try again next time, from exactly where it left off.



## One Bad Vendor Can't Sink the Rest



Every vendor is inspected independently. If one serves garbage data or fails its seal check, that failure is logged and the inspector moves on — untouched, the other vendors' data keeps flowing in normally.



## Quick Reference: What Could Go Wrong, and What Stops It



|If someone tried to...|This happens|
|-|-|
|Edit a delivery batch after it was published|Fingerprint no longer matches → rejected|
|Edit the summary to match a forged batch|Seal breaks → rejected|
|Forge a summary using their own fake stamp|Stamp doesn't match the vendor's known seal → rejected|
|Replay an old, previously-valid summary to hide a recall|Version number would go backwards → rejected|
|Pass off one vendor's data as another's|Vendor identity embedded in the data doesn't match → rejected|
|Flood the inspector with an endless fake response|Download is capped at a fixed size → aborted|

## 

## What This Deliberately Doesn't Solve



A vendor can seal a lie — the seal only proves *who sent it*, not that they were telling the truth. And if a vendor's private stamp is ever stolen, whoever holds it can forge convincing data in that vendor's name. These are known, out-of-scope limits, not oversights.

\---



### In one sentence



An automated inspector that visits independent vendors' public postings, verifies with cryptographic seals and fingerprints that nothing was forged or tampered with, and merges only what survives that check into one searchable, crash-safe ledger.

