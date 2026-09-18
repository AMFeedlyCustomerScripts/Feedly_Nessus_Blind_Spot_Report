# Feedly → Nessus Blind Spot Report

Finds the CVEs Feedly tracks in your streams that have **no Nessus plugin coverage**.
That set is your scanner blind spot.

Built for vulnerability management teams who run Nessus and want to know which
tracked CVEs their scanner cannot see.

---

## Install

```bash
pip install -r requirements.txt
export FEEDLY_TOKEN="your-feedly-api-token"
```

The token is read from `FEEDLY_TOKEN`, then `FEEDLY_API_KEY`, then a `.env`
file in the working directory or the script directory. It is never hardcoded.

---

## Quick start

```bash
# 1. Sanity-check the coverage field against known CVEs before trusting a report
python3 feedly_nessus_blindspot.py --inspect-detected-by \
    CVE-2024-3400 CVE-2021-44228 CVE-2024-21412 CVE-2023-4966 CVE-2024-9999

# 2. First full pull across a folder and its child feeds
python3 feedly_nessus_blindspot.py \
    --stream-id "enterprise/YOUR_ENTERPRISE/category/YOUR_FOLDER_ID" \
    --stream-id "enterprise/YOUR_ENTERPRISE/tag/YOUR_AI_FEED_ID" \
    --output blindspots.csv

# 3. Subsequent delta runs, using the previous run's timestamp (epoch ms)
python3 feedly_nessus_blindspot.py --config config.yaml --newer-than 1758153600000

# 4. The finding that actually matters: uncovered CVEs with a live exploit
python3 feedly_nessus_blindspot.py --config config.yaml \
    --blind-spots-only --exploited-only --json-output report.json
```

---

## The three coverage buckets

One question decides the bucket: **is there a Nessus plugin for this CVE?**

| Bucket | Meaning | `detectedBy` state |
|---|---|---|
| **Nessus covered** | A Nessus plugin detects this CVE. Plugin IDs captured. | Contains a Nessus entry |
| **Blind spot** | **No Nessus plugin.** This is the gap being reported. | Populated by other scanners only, *or* missing / `null` / `[]` |
| **Unknown** | No insight card could be retrieved, so nothing can be said either way. | Card not returned by the API |

A blind spot is a blind spot whether or not something else detects the CVE —
if Nessus has no plugin, the scanner is blind to it. What other scanners do
does not change the bucket, so it is recorded separately in the `evidence`
column:

| `evidence` | Meaning |
|---|---|
| `other scanners detect it` | Qualys/nuclei/etc. detect this and Nessus does not. Strongest evidence the gap is real — Feedly demonstrably has coverage data here and Nessus is absent from it. |
| `no scanner data` | No detection data for any scanner. Still a CVE Nessus is not known to detect, but it could equally be a hole in the coverage data. |

Use `--confirmed-only` to narrow a report to the `other scanners detect it`
subset when you want the highest-confidence findings.

### Verified field structure

The API reference documents `detectedBy` as an array of detection objects but
does not publish the key names inside it. Probed live against
`POST /v3/entities/.mget` on 2026-09-18:

```json
"detectedBy": [
  {"detectionId": "193255", "scannerName": "nessus"},
  {"detectionId": "731378", "scannerName": "qualys"},
  {"detectionId": "http/cves/2024/CVE-2024-3400.yaml", "scannerName": "nuclei"}
]
```

Observed `scannerName` values are lowercase: `nessus`, `qualys`, `nuclei`.
The filter matches **case-insensitively** and probes a list of candidate key
names (`scannerName`, `scanner`, `name`, `source`, `vendor`, …) rather than
assuming a literal, so it survives a schema change. Re-run
`--inspect-detected-by` at any time to confirm the live shape.

---

## Pipeline

| Stage | What it does |
|---|---|
| 1. Collect | `GET /v3/streams/contents` at `count=250`, paging on `continuation` until absent, across every configured stream ID. `--newer-than` makes it a delta run. |
| 2. Extract | CVE entities from structured article fields **first**; regex over title and summary as a **secondary** pass. Every CVE is tagged `entity`, `regex`, or both, so regex false positives stay traceable. Normalized uppercase, deduped. |
| 3. Enrich | `POST /v3/entities/.mget` in chunks of 100. `GET /v3/entities/{id}` is used **only** for IDs the bulk call misses. `withStats` is deliberately not passed. |
| 4. Classify | The three-bucket filter above. |
| 5. Output | CSV primary, JSON optional, sorted exploit-status-then-EPSS. |

### Rate limiting

Backoff is exponential on 429 and 5xx, honouring `Retry-After` when present.
Between calls the client reads Feedly's `x-ratelimit-limit`,
`x-ratelimit-count`, and `x-ratelimit-reset` headers and throttles on the real
remaining quota rather than sleeping blindly. Quota use is printed at the end
of every run.

---

## Output columns

`cve_id`, `cvss_v3_base_score`, `cvss_category_estimate` (populated only where
a real CVSS v3 score is absent), `epss`, `cve_status`, `patched`,
`exploit_status`, `coverage`, `evidence`, `nessus_plugin_ids`,
`other_scanners`, `detection_count`, `extraction_method`, `article_mentions`,
`source_streams`, `feedly_card_url`.

Rows are sorted by exploit status, then EPSS descending, so the vuln
management team triages the blind spots that actually matter first:

| Rank | `exploit_status` | Derived from |
|---|---|---|
| 0 | Exploited (CISA KEV) | `cisaKevAddedDate` |
| 1 | Exploited in the wild | `exploitedAt`, `proofOfExploits` |
| 2 | Exploit available | `exploits`, `newExploits` |
| 3 | Proof of concept | `proofOfConcepts` |
| 4 | None | — |

> **Note on `overall_label`:** this field does not exist on the CVE insight
> card. Every field on the card was walked recursively during development and
> it was not present on any sample. Exploit status is therefore derived from
> the concrete fields above. The script still looks for `overall_label`
> anywhere on the card and prefers it if found, so it will pick the field up
> automatically if Feedly starts returning it.

---

## Filters

| Flag | Effect |
|---|---|
| *(default)* | Drops `Rejected` and `Likely Rejected` `cveStatus`. These are CVE IDs never formally assigned in MITRE/NVD; a blind spot report full of them destroys trust on the first run. |
| `--include-rejected` | Keeps them. |
| `--exploited-only` | Only CVEs with a KEV entry, in-the-wild reporting, exploit code, or a PoC. An uncovered CVE with a working exploit is the finding; an uncovered CVE with nothing behind it is noise. |
| `--blind-spots-only` | Emits only the Blind spot bucket — every CVE with no Nessus plugin. |
| `--confirmed-only` | Narrows blind spots to those another scanner detects (`evidence = other scanners detect it`), the highest-confidence findings. |

---

## All flags

```
--config PATH             YAML config with stream_ids and settings
--stream-id ID            Stream to pull (repeatable; folders and feeds both)
--newer-than EPOCH_MS     Delta run: only articles newer than this
--max-articles N          Stop after N articles per stream (testing safeguard)
--output, -o PATH         CSV output path (default: nessus_blindspots.csv)
--json-output PATH        Also write JSON
--blind-spots-only        Emit only the Blind spot bucket (no Nessus plugin)
--confirmed-only          Narrow to blind spots another scanner detects
--exploited-only          Only CVEs with a known exploit or PoC
--include-rejected        Keep Rejected / Likely Rejected CVE IDs
--inspect-detected-by ... Print raw detectedBy for sample CVEs and exit
--dry-run                 Run every stage, write no files
--verbose, -v             Debug logging
```

---

## Important caveat

`detectedBy` reflects the scanner-coverage data Feedly has mapped, not a
complete mirror of the Tenable plugin catalog. **Blind spot** means Feedly has
no Nessus plugin recorded for that CVE — the right place to start, but confirm
against the Tenable plugin database before treating it as a definitive
coverage failure.

The `evidence` column is what tells you how much weight to put on each row.
`other scanners detect it` is the strong signal: Feedly demonstrably holds
coverage data for that CVE and Nessus is not in it. `no scanner data` is
weaker, because an empty `detectedBy` can equally mean Feedly has not mapped
coverage for that CVE yet. Both are genuine blind spots for triage purposes;
only the first is strong evidence on its own. Start with
`--blind-spots-only --confirmed-only --exploited-only`, then widen.

---

© 2025 Feedly, Inc. All rights reserved. See the disclaimer in the script header.
