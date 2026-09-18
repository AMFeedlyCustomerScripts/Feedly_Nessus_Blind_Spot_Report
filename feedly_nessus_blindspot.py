#!/usr/bin/env python3
"""
Feedly Nessus Blind Spot Report - Find CVEs Feedly tracks that Nessus cannot detect

© 2025 Feedly, Inc. All rights reserved.

DISCLAIMERS. THE API SCRIPTS ARE PROVIDED "AS IS" FOR YOUR INTERNAL BUSINESS
USE ONLY. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE API SCRIPTS
IS WITH YOU. YOU AGREE THAT YOUR USE OF THE API SCRIPTS WILL BE AT YOUR SOLE
RISK. TO THE FULLEST EXTENT PERMITTED BY LAW, FEEDLY DISCLAIMS ALL WARRANTIES,
EXPRESS OR IMPLIED, IN CONNECTION WITH THE API SCRIPTS AND YOUR USE THEREOF,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. FEEDLY MAKES NO
WARRANTIES OR REPRESENTATIONS ABOUT THE ACCURACY OR COMPLETENESS OF THE API
SCRIPTS AND NO REPRESENTATIONS THAT THE API SCRIPTS ARE NOT OTHERWISE
ENCUMBERED BY ANY THIRD PARTY LICENSE, INCLUDING ANY OPEN-SOURCE LICENSE.
FEEDLY ASSUMES NO LIABILITY OR RESPONSIBILITY FOR ANY: (1) ERRORS, MISTAKES,
OR INACCURACIES; (2) PERSONAL INJURY OR PROPERTY DAMAGE, OF ANY NATURE
WHATSOEVER, RESULTING FROM YOUR USE OF THE API SCRIPTS; (3) ANY UNAUTHORIZED
ACCESS TO OR USE OF API SCRIPTS; (4) ANY INTERRUPTION OR CESSATION OF
TRANSMISSION TO OR FROM THE API SCRIPTS; (5) ANY BUGS, VIRUSES, TROJAN HORSES,
OR THE LIKE WHICH MAY BE TRANSMITTED TO OR THROUGH THE API SCRIPTS BY ANY
THIRD PARTY; OR (6) ANY ERRORS OR OMISSIONS IN THE API SCRIPTS OR FOR ANY LOSS
OR DAMAGE OF ANY KIND INCURRED AS A RESULT OF THE USE OF THE API SCRIPTS.

LIMITATION OF LIABILITY. IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY DAMAGES.
FURTHER, IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY CONSEQUENTIAL, INCIDENTAL
OR INDIRECT DAMAGES, INCLUDING, WITHOUT LIMITATION, ANY LOSS OF DATA, OR LOSS
OF PROFITS OR LOST SAVINGS, ARISING OUT OF USE OF OR INABILITY TO USE THE
LICENSED PRODUCT, EVEN IF FEEDLY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGES, OR FOR ANY CLAIM BY ANY THIRD PARTY.

YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTAND THESE TERMS AND AGREE TO BE
BOUND BY THEM. YOU FURTHER AGREE THAT THESE TERMS ARE THE COMPLETE AND
EXCLUSIVE STATEMENT OF THE AGREEMENT BETWEEN YOU AND FEEDLY FOR THE USE OF THE
API SCRIPTS, AND THESE TERMS SUPERSEDE ANY PRIOR AGREEMENT, ORAL OR WRITTEN,
AND ANY OTHER COMMUNICATIONS RELATING TO THE SUBJECT MATTER HEREOF.
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None
    print("WARNING: PyYAML not installed. Config file loading disabled.")


# =============================================================================
# CONFIGURATION
# =============================================================================

def load_api_key() -> str:
    """
    Load API key from environment variable or .env file.
    Priority: FEEDLY_TOKEN env var > FEEDLY_API_KEY env var > .env file > placeholder
    """
    for var in ("FEEDLY_TOKEN", "FEEDLY_API_KEY"):
        api_key = os.environ.get(var)
        if api_key:
            return api_key

    env_locations = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]

    for env_path in env_locations:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        for var in ("FEEDLY_TOKEN=", "FEEDLY_API_KEY="):
                            if line.startswith(var):
                                key = line.split("=", 1)[1].strip()
                                if (key.startswith('"') and key.endswith('"')) or \
                                   (key.startswith("'") and key.endswith("'")):
                                    key = key[1:-1]
                                if key:
                                    return key
            except Exception:
                pass

    return "APIKEYHERE"  # Fallback placeholder


API_KEY = load_api_key()

# API Configuration
BASE_URL = "https://api.feedly.com"
MAX_RETRIES = 5
RETRY_DELAY = 2           # seconds
RATE_LIMIT_DELAY = 0.5    # seconds between API calls
STREAM_PAGE_SIZE = 250    # max articles per /v3/streams/contents page
MGET_CHUNK_SIZE = 100     # CVE IDs per /v3/entities/.mget call
RATE_LIMIT_FLOOR = 0.02   # pause when <2% of the hourly quota remains

# The scanner we are measuring coverage against. Matched case-insensitively
# as a substring, so "Nessus", "nessus", "tenable_nessus" all resolve.
TARGET_SCANNER = "nessus"

# Verified live against /v3/entities/.mget on 2026-09-18. detectedBy is a list
# of objects shaped {"scannerName": "nessus", "detectionId": "193255"}. The key
# names are not published in the reference, so we probe a list of candidates
# rather than hardcoding one.
SCANNER_NAME_KEYS = ("scannerName", "scanner", "name", "source", "vendor",
                     "tool", "product", "detector", "label")
DETECTION_ID_KEYS = ("detectionId", "pluginId", "plugin_id", "id",
                     "detection_id", "pluginID", "signatureId")

# CVE status values Feedly assigns to IDs that were never formally allocated.
# Filtered out by default: a blind spot report full of fabricated CVE IDs
# destroys trust in the output on the first run.
REJECTED_STATUSES = {"rejected", "likely rejected"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Coverage buckets. One question decides the bucket: is there a Nessus plugin?
#
#   Nessus covered - a Nessus entry exists in detectedBy. Plugin IDs captured.
#   Blind spot     - no Nessus entry. This covers both the case where other
#                    scanners detect the CVE and Nessus does not, and the case
#                    where there is no detection data at all. Either way Nessus
#                    is not detecting it, which is the gap being reported.
#   Unknown        - no insight card could be retrieved for the CVE, so nothing
#                    can be said about coverage either way.
COVERED = "Nessus covered"
BLIND_SPOT = "Blind spot"
UNKNOWN = "Unknown"

# Recorded alongside the bucket so a blind spot backed by other scanners can be
# told apart from one backed by no data at all. This is supporting evidence,
# not a separate bucket.
EVIDENCE_OTHER_SCANNERS = "other scanners detect it"
EVIDENCE_NO_DATA = "no scanner data"
EVIDENCE_NESSUS = "nessus plugin"
EVIDENCE_NO_CARD = "no insight card"

VERBOSE = False


def vlog(msg: str) -> None:
    """Print only when --verbose is set."""
    if VERBOSE:
        print(f"  [debug] {msg}")


# =============================================================================
# API CLIENT
# =============================================================================

class FeedlyClient:
    """
    Thin client for the Feedly API endpoints this report needs.

      GET  /v3/streams/contents   - paged article stream
      POST /v3/entities/.mget     - bulk CVE insight cards (primary enrichment)
      GET  /v3/entities/{id}      - single CVE insight card (fallback only)
    """

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })
        self.calls = 0
        self.rate_limit: Optional[int] = None
        self.rate_count: Optional[int] = None
        self.rate_reset: Optional[int] = None

    # -- rate limiting -----------------------------------------------------

    def _read_rate_headers(self, response: requests.Response) -> None:
        """
        Record Feedly's rate limit headers so we can throttle on real numbers
        instead of sleeping blindly between calls.

        Feedly returns x-ratelimit-limit (hourly quota), x-ratelimit-count
        (calls used) and x-ratelimit-reset (seconds until the window resets).
        """
        def as_int(name: str) -> Optional[int]:
            raw = response.headers.get(name)
            try:
                return int(raw) if raw is not None else None
            except (TypeError, ValueError):
                return None

        self.rate_limit = as_int("x-ratelimit-limit") or self.rate_limit
        self.rate_count = as_int("x-ratelimit-count")
        self.rate_reset = as_int("x-ratelimit-reset")

    def _throttle(self) -> None:
        """Back off proactively when the remaining quota gets thin."""
        if not self.rate_limit or self.rate_count is None:
            time.sleep(RATE_LIMIT_DELAY)
            return

        remaining = self.rate_limit - self.rate_count
        if remaining <= 0:
            wait = min(self.rate_reset or 60, 300)
            print(f"  Quota exhausted ({self.rate_count}/{self.rate_limit}). "
                  f"Waiting {wait}s for reset...")
            time.sleep(wait)
        elif remaining < self.rate_limit * RATE_LIMIT_FLOOR:
            vlog(f"quota low: {remaining} of {self.rate_limit} left, slowing down")
            time.sleep(RATE_LIMIT_DELAY * 4)
        else:
            time.sleep(RATE_LIMIT_DELAY)

    def quota_summary(self) -> str:
        if self.rate_limit and self.rate_count is not None:
            return (f"{self.rate_count}/{self.rate_limit} API calls used this window "
                    f"(resets in {self.rate_reset}s)")
        return f"{self.calls} API calls made"

    # -- request -----------------------------------------------------------

    def _request(self, method: str, endpoint: str, data=None, params=None,
                 retries: int = MAX_RETRIES) -> Any:
        """Make an API request with exponential backoff on 429 and 5xx."""
        url = f"{BASE_URL}{endpoint}"

        for attempt in range(retries):
            try:
                self.calls += 1
                response = self.session.request(
                    method, url, json=data, params=params, timeout=90
                )
                self._read_rate_headers(response)

                # Handle rate limiting: honour Retry-After, else exponential backoff
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        wait = int(retry_after)
                    except (TypeError, ValueError):
                        wait = RETRY_DELAY * (2 ** attempt)
                    print(f"  Rate limited (429). Waiting {wait}s...")
                    time.sleep(wait)
                    continue

                # Retry transient server errors, fail fast on client errors
                if response.status_code >= 500:
                    if attempt < retries - 1:
                        wait = RETRY_DELAY * (2 ** attempt)
                        vlog(f"HTTP {response.status_code} on {endpoint}, retrying in {wait}s")
                        time.sleep(wait)
                        continue
                    raise Exception(f"API Error {response.status_code}: {response.text[:200]}")

                if response.status_code >= 400:
                    raise Exception(f"API Error {response.status_code}: {response.text[:200]}")

                return response.json()

            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    wait = RETRY_DELAY * (2 ** attempt)
                    vlog(f"network error {e}, retrying in {wait}s")
                    time.sleep(wait)
                    continue
                raise

        raise Exception(f"Exhausted {retries} retries for {endpoint}")

    # -- endpoints ---------------------------------------------------------

    def stream_contents(self, stream_id: str, count: int = STREAM_PAGE_SIZE,
                        continuation: Optional[str] = None,
                        newer_than: Optional[int] = None) -> Dict[str, Any]:
        """GET /v3/streams/contents for one page of a stream."""
        params: Dict[str, Any] = {"streamId": stream_id, "count": count}
        if continuation:
            params["continuation"] = continuation
        if newer_than:
            params["newerThan"] = newer_than
        return self._request("GET", "/v3/streams/contents", params=params)

    def entities_mget(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """
        POST /v3/entities/.mget - bulk CVE insight cards.

        Body is a bare JSON array of CVE ID strings. Unknown IDs are silently
        omitted from the response rather than returned as errors. withStats is
        deliberately not passed: it pulls references and chatter this report
        does not use and makes the payload far heavier.
        """
        result = self._request("POST", "/v3/entities/.mget", data=cve_ids)
        if isinstance(result, list):
            return [r for r in result if isinstance(r, dict)]
        if isinstance(result, dict):
            return [result]
        return []

    def entity_get(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """GET /v3/entities/{id} - single card, used only for bulk misses."""
        encoded = urllib.parse.quote(cve_id, safe="")
        try:
            result = self._request("GET", f"/v3/entities/{encoded}", retries=2)
            return result if isinstance(result, dict) else None
        except Exception as e:
            vlog(f"single-card fallback failed for {cve_id}: {e}")
            return None


# =============================================================================
# STAGE 1: COLLECT ARTICLES
# =============================================================================

def collect_articles(client: FeedlyClient, stream_ids: List[str],
                     newer_than: Optional[int] = None,
                     max_articles: Optional[int] = None) -> List[Tuple[Dict[str, Any], str]]:
    """
    Page every configured stream to exhaustion and return (article, stream_id)
    pairs. A folder stream ID and its child feed IDs return overlapping but not
    identical sets, so both are worth configuring; dedupe happens at the CVE
    level in stage 2, not here.
    """
    collected: List[Tuple[Dict[str, Any], str]] = []

    for stream_id in stream_ids:
        print(f"\n  Stream: {stream_id}")
        continuation: Optional[str] = None
        page = 0
        stream_total = 0

        while True:
            page += 1
            try:
                data = client.stream_contents(
                    stream_id, count=STREAM_PAGE_SIZE,
                    continuation=continuation, newer_than=newer_than,
                )
            except Exception as e:
                print(f"    ERROR reading stream after {stream_total} articles: {e}")
                break

            items = data.get("items") or []
            for item in items:
                collected.append((item, stream_id))
            stream_total += len(items)
            print(f"    page {page}: {len(items)} articles (running total {stream_total})")

            if max_articles and stream_total >= max_articles:
                print(f"    reached --max-articles limit of {max_articles}, stopping")
                break

            continuation = data.get("continuation")
            if not continuation:
                break

            client._throttle()

        print(f"    done: {stream_total} articles")

    return collected


# =============================================================================
# STAGE 2: EXTRACT CVE IDS
# =============================================================================

def extract_cves_from_article(article: Dict[str, Any]) -> Dict[str, Set[str]]:
    """
    Extract CVE IDs from one article, returning {CVE_ID: {extraction methods}}.

    Structured entity fields are the primary source. A regex over title and
    summary runs as a secondary pass only, and IDs found that way are tagged
    'regex' so false positives stay traceable in the output. A CVE seen both
    ways carries both tags; a CVE tagged 'regex' alone had no entity backing it.
    """
    found: Dict[str, Set[str]] = {}

    def add(cve_id: str, method: str) -> None:
        found.setdefault(cve_id.upper(), set()).add(method)

    # -- Primary: structured entity fields --------------------------------
    entity_fields = ("entities", "commonTopics", "featuredEntities",
                     "vulnerabilities", "nlpEntities")

    for field in entity_fields:
        for entity in article.get(field) or []:
            if not isinstance(entity, dict):
                if isinstance(entity, str) and CVE_RE.fullmatch(entity):
                    add(entity, "entity")
                continue

            entity_type = str(entity.get("type") or "").lower()
            is_vuln_type = "cve" in entity_type or "vulnerab" in entity_type

            for key in ("label", "cveId", "cve_id", "cveid", "id", "name"):
                val = entity.get(key)
                if not isinstance(val, str):
                    continue
                match = CVE_RE.search(val)
                if match and (is_vuln_type or CVE_RE.fullmatch(val.strip())):
                    add(match.group(), "entity")

    # Plain keyword lists occasionally carry bare CVE IDs
    for keyword in article.get("keywords") or []:
        if isinstance(keyword, str) and CVE_RE.fullmatch(keyword.strip()):
            add(keyword.strip(), "entity")

    # -- Secondary: regex over title and summary --------------------------
    text_parts = [article.get("title") or ""]
    summary = article.get("summary")
    if isinstance(summary, dict):
        text_parts.append(summary.get("content") or "")
    elif isinstance(summary, str):
        text_parts.append(summary)

    for match in CVE_RE.findall(" ".join(text_parts)):
        add(match, "regex")

    return found


def extract_all_cves(articles: List[Tuple[Dict[str, Any], str]]
                     ) -> Dict[str, Dict[str, Any]]:
    """
    Fold every article's CVEs into one deduplicated map:
        {CVE_ID: {"methods": set, "streams": set, "article_count": int}}
    """
    index: Dict[str, Dict[str, Any]] = {}

    for article, stream_id in articles:
        for cve_id, methods in extract_cves_from_article(article).items():
            record = index.setdefault(cve_id, {
                "methods": set(), "streams": set(), "article_count": 0,
            })
            record["methods"].update(methods)
            record["streams"].add(stream_id)
            record["article_count"] += 1

    return index


# =============================================================================
# STAGE 3: ENRICH
# =============================================================================

def enrich_cves(client: FeedlyClient, cve_ids: List[str]
                ) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """
    Fetch insight cards for every CVE via the bulk endpoint, chunked. Only the
    IDs the bulk call omits are retried one at a time with GET /v3/entities.

    Returns (cards_by_cve_id, not_found_ids).
    """
    cards: Dict[str, Dict[str, Any]] = {}
    ordered = sorted(cve_ids)

    chunks = [ordered[i:i + MGET_CHUNK_SIZE]
              for i in range(0, len(ordered), MGET_CHUNK_SIZE)]

    for n, chunk in enumerate(chunks, 1):
        print(f"  bulk chunk {n}/{len(chunks)} ({len(chunk)} CVEs)...", end="", flush=True)
        try:
            for card in client.entities_mget(chunk):
                cve_id = card_cve_id(card)
                if cve_id:
                    cards[cve_id] = card
            print(f" {len(cards)} cards so far")
        except Exception as e:
            print(f" FAILED: {e}")
        client._throttle()

    # Fall back to the single-card endpoint only for what bulk missed
    missing = [c for c in ordered if c not in cards]
    not_found: List[str] = []

    if missing:
        print(f"  {len(missing)} CVEs missed by bulk, retrying individually...")
        for cve_id in missing:
            card = client.entity_get(cve_id)
            if card and card_cve_id(card):
                cards[card_cve_id(card)] = card
            else:
                not_found.append(cve_id)
            client._throttle()

    return cards, not_found


def card_cve_id(card: Dict[str, Any]) -> str:
    """Pull the canonical CVE ID off an insight card."""
    for key in ("cveid", "cveId", "label"):
        val = card.get(key)
        if isinstance(val, str):
            match = CVE_RE.search(val)
            if match:
                return match.group().upper()
    entity_id = card.get("id")
    if isinstance(entity_id, str):
        match = CVE_RE.search(entity_id)
        if match:
            return match.group().upper()
    return ""


# =============================================================================
# STAGE 4: THE COVERAGE FILTER
# =============================================================================

def scanner_entry_name(entry: Any) -> str:
    """
    Pull the scanner name out of one detectedBy entry without assuming a key.

    Live cards use {"scannerName": "nessus", "detectionId": "193255"}, but the
    reference does not publish the key names, so we probe known candidates and
    fall back to scanning every string value on the object.
    """
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return ""

    for key in SCANNER_NAME_KEYS:
        val = entry.get(key)
        if isinstance(val, str) and val.strip():
            return val
        # Some shapes nest the scanner as {"scanner": {"label": "nessus"}}
        if isinstance(val, dict):
            for sub in ("label", "name", "id"):
                if isinstance(val.get(sub), str) and val[sub].strip():
                    return val[sub]

    # Last resort: any string value that names a scanner we recognise
    for val in entry.values():
        if isinstance(val, str) and TARGET_SCANNER in val.lower():
            return val
    return ""


def scanner_entry_detection_id(entry: Any) -> str:
    """Pull the plugin / detection ID out of one detectedBy entry."""
    if not isinstance(entry, dict):
        return ""
    for key in DETECTION_ID_KEYS:
        val = entry.get(key)
        if isinstance(val, (str, int)) and str(val).strip():
            return str(val)
    return ""


def classify_coverage(card: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide the bucket on one question: does a Nessus plugin detect this CVE?

    No Nessus entry means blind spot, whether or not other scanners detect it.
    What other scanners do is recorded as supporting evidence, because a gap
    backed by a Qualys detection is a stronger finding than one backed by no
    data at all - but it is still the same gap.
    """
    detected_by = card.get("detectedBy")

    # No detection data for anything, Nessus included: still a blind spot
    if not isinstance(detected_by, list) or len(detected_by) == 0:
        return {
            "bucket": BLIND_SPOT,
            "evidence": EVIDENCE_NO_DATA,
            "plugin_ids": [],
            "other_scanners": [],
            "detection_count": 0,
        }

    nessus_plugin_ids: List[str] = []
    other_scanners: Set[str] = set()

    for entry in detected_by:
        name = scanner_entry_name(entry)
        if not name:
            continue
        if TARGET_SCANNER in name.lower():
            detection_id = scanner_entry_detection_id(entry)
            if detection_id:
                nessus_plugin_ids.append(detection_id)
        else:
            other_scanners.add(name.lower())

    if nessus_plugin_ids or any(
        TARGET_SCANNER in scanner_entry_name(e).lower() for e in detected_by
    ):
        return {
            "bucket": COVERED,
            "evidence": EVIDENCE_NESSUS,
            "plugin_ids": sorted(set(nessus_plugin_ids)),
            "other_scanners": sorted(other_scanners),
            "detection_count": len(detected_by),
        }

    return {
        "bucket": BLIND_SPOT,
        "evidence": EVIDENCE_OTHER_SCANNERS,
        "plugin_ids": [],
        "other_scanners": sorted(other_scanners),
        "detection_count": len(detected_by),
    }


# =============================================================================
# EXPLOIT STATUS
# =============================================================================

# Ranked worst-first so the sort puts the findings that matter at the top.
# CISA KEV is split out from general in-the-wild reporting because exploitedAt
# is populated by any exploitation mention, which puts a CVE with an EPSS of
# 0.005 in the same tier as a confirmed KEV entry unless they are separated.
KEV = "Exploited (CISA KEV)"
ITW = "Exploited in the wild"
EXPLOIT_AVAILABLE = "Exploit available"
POC = "Proof of concept"
NO_EXPLOIT = "None"

EXPLOIT_RANK = {
    KEV: 0,
    ITW: 1,
    EXPLOIT_AVAILABLE: 2,
    POC: 3,
    NO_EXPLOIT: 4,
}


def find_overall_label(card: Dict[str, Any]) -> str:
    """
    Look for an overall_label field anywhere on the card.

    Probed live on 2026-09-18 and it is not present on any CVE insight card,
    so this returns "" in practice and exploit status is derived instead. Kept
    because it costs nothing and will pick the field up automatically if
    Feedly starts returning it.
    """
    stack: List[Any] = [card]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, val in node.items():
                if key.lower() in ("overall_label", "overalllabel"):
                    if isinstance(val, str) and val.strip():
                        return val.strip()
                    if isinstance(val, dict):
                        for sub in ("label", "value", "name"):
                            if isinstance(val.get(sub), str):
                                return val[sub]
                stack.append(val)
        elif isinstance(node, list):
            stack.extend(node)
    return ""


def exploit_status(card: Dict[str, Any]) -> str:
    """
    Derive exploit presence from the fields the insight card actually carries.

    Prefers overall_label when present; otherwise escalates through active
    exploitation, then working exploits, then proof-of-concept code.
    """
    label = find_overall_label(card)
    if label:
        lowered = label.lower()
        if "kev" in lowered:
            return KEV
        if "wild" in lowered or "exploited" in lowered or "weaponiz" in lowered:
            return ITW
        if "exploit" in lowered:
            return EXPLOIT_AVAILABLE
        if "poc" in lowered or "concept" in lowered:
            return POC
        if "none" in lowered or lowered.startswith("no"):
            return NO_EXPLOIT
        return label

    # CISA KEV is a confirmed, government-attested exploitation record
    if card.get("cisaKevAddedDate"):
        return KEV
    # exploitedAt / proofOfExploits are Feedly's exploitation *reporting*
    if card.get("exploitedAt") or card.get("proofOfExploits"):
        return ITW
    # exploits / newExploits are links to actual exploit code
    if card.get("exploits") or card.get("newExploits"):
        return EXPLOIT_AVAILABLE
    if card.get("proofOfConcepts"):
        return POC
    return NO_EXPLOIT


# =============================================================================
# ROW BUILDING
# =============================================================================

def epss_float(card: Dict[str, Any]) -> float:
    """EPSS arrives as a string on the card; coerce for sorting."""
    raw = card.get("epssScore")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def cvss_base_score(card: Dict[str, Any]) -> Optional[float]:
    cvss = card.get("cvssV3")
    if isinstance(cvss, dict):
        score = cvss.get("baseScore")
        if isinstance(score, (int, float)):
            return float(score)
    return None


def feedly_card_url(cve_id: str) -> str:
    entity_id = f"vulnerability/m/entity/{cve_id}"
    return f"https://feedly.com/i/entity/{urllib.parse.quote(entity_id, safe='')}"


def build_row(cve_id: str, card: Dict[str, Any],
              extraction: Dict[str, Any]) -> Dict[str, Any]:
    """Assemble one output row from an insight card plus stage-2 provenance."""
    coverage = classify_coverage(card)
    base_score = cvss_base_score(card)
    status = exploit_status(card)

    return {
        "cve_id": cve_id,
        "cvss_v3_base_score": base_score if base_score is not None else "",
        "cvss_category_estimate": (card.get("cvssCategoryEstimate") or "")
                                  if base_score is None else "",
        "epss": card.get("epssScore") or "",
        "cve_status": card.get("cveStatus") or "",
        "patched": card.get("patched") if isinstance(card.get("patched"), bool) else "",
        "exploit_status": status,
        "coverage": coverage["bucket"],
        "evidence": coverage["evidence"],
        "nessus_plugin_ids": ";".join(coverage["plugin_ids"]),
        "other_scanners": ";".join(coverage["other_scanners"]),
        "detection_count": coverage["detection_count"],
        "extraction_method": ";".join(sorted(extraction.get("methods", []))),
        "article_mentions": extraction.get("article_count", 0),
        "source_streams": ";".join(sorted(extraction.get("streams", []))),
        "feedly_card_url": feedly_card_url(cve_id),
        # Sort keys, stripped before writing
        "_exploit_rank": EXPLOIT_RANK.get(status, EXPLOIT_RANK[NO_EXPLOIT]),
        "_epss": epss_float(card),
    }


def build_unknown_row(cve_id: str, extraction: Dict[str, Any]) -> Dict[str, Any]:
    """
    Row for a CVE that appeared in the streams but has no Feedly insight card.

    Nothing can be said about Nessus coverage for these, so they are Unknown
    rather than blind spots. They are still reported: a CVE the team is reading
    about that Feedly cannot resolve is worth someone looking at.
    """
    return {
        "cve_id": cve_id,
        "cvss_v3_base_score": "",
        "cvss_category_estimate": "",
        "epss": "",
        "cve_status": "",
        "patched": "",
        "exploit_status": NO_EXPLOIT,
        "coverage": UNKNOWN,
        "evidence": EVIDENCE_NO_CARD,
        "nessus_plugin_ids": "",
        "other_scanners": "",
        "detection_count": 0,
        "extraction_method": ";".join(sorted(extraction.get("methods", []))),
        "article_mentions": extraction.get("article_count", 0),
        "source_streams": ";".join(sorted(extraction.get("streams", []))),
        "feedly_card_url": feedly_card_url(cve_id),
        "_exploit_rank": EXPLOIT_RANK[NO_EXPLOIT],
        "_epss": 0.0,
    }


def sort_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Exploit status first, then EPSS descending, so triage order is the output order."""
    return sorted(rows, key=lambda r: (r["_exploit_rank"], -r["_epss"], r["cve_id"]))


# =============================================================================
# OUTPUT
# =============================================================================

CSV_COLUMNS = [
    "cve_id", "cvss_v3_base_score", "cvss_category_estimate", "epss",
    "cve_status", "patched", "exploit_status", "coverage", "evidence",
    "nessus_plugin_ids", "other_scanners", "detection_count",
    "extraction_method", "article_mentions", "source_streams", "feedly_card_url",
]


def write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"\n  CSV written: {path} ({len(rows)} rows)")


def write_json(rows: List[Dict[str, Any]], path: str,
               summary: Dict[str, Any]) -> None:
    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "cves": clean}, f, indent=2)
    print(f"  JSON written: {path} ({len(clean)} records)")


def print_summary(rows: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    print("\n" + "=" * 70)
    print("NESSUS BLIND SPOT SUMMARY")
    print("=" * 70)
    print(f"  Articles read                : {summary['articles']}")
    print(f"  Unique CVEs extracted        : {summary['cves_extracted']}")
    print(f"    via structured entities    : {summary['via_entity']}")
    print(f"    via regex only             : {summary['via_regex_only']}")
    print(f"  Insight cards retrieved      : {summary['cards']}")
    print(f"  Dropped (rejected CVE IDs)   : {summary['dropped_rejected']}")
    print(f"  Dropped (no exploit)         : {summary['dropped_no_exploit']}")
    print("-" * 70)
    print(f"  Nessus covered               : {summary['covered']}")
    print(f"  BLIND SPOT                   : {summary['blind_spot']}")
    print(f"    other scanners detect it   : {summary['blind_spot_confirmed']}")
    print(f"    no scanner data at all     : {summary['blind_spot_no_data']}")
    print(f"  Unknown (no insight card)    : {summary['unknown']}")
    print("=" * 70)

    top = [r for r in rows if r["coverage"] == BLIND_SPOT][:10]
    if top:
        print("\n  Top blind spots by triage order:")
        print(f"    {'CVE':<18} {'EXPLOIT':<22} {'EPSS':>8}  {'CVSS':>5}  EVIDENCE")
        for r in top:
            evidence = r["evidence"]
            if r["other_scanners"]:
                evidence = f"{evidence} ({r['other_scanners'][:24]})"
            print(f"    {r['cve_id']:<18} {r['exploit_status']:<22} "
                  f"{str(r['epss'])[:8]:>8}  {str(r['cvss_v3_base_score']):>5}  "
                  f"{evidence}")


# =============================================================================
# CLI
# =============================================================================

def load_config(path: str) -> Dict[str, Any]:
    if not yaml:
        print("ERROR: --config requires PyYAML. Install with: pip install pyyaml")
        sys.exit(1)
    if not os.path.exists(path):
        print(f"ERROR: config file not found: {path}")
        sys.exit(1)
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Report CVEs tracked by Feedly that have no Nessus plugin coverage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pull across a folder and its child feeds
  %(prog)s --stream-id "enterprise/YOUR_ENTERPRISE/category/YOUR_FOLDER_ID" \\
           --stream-id "feed/https://example.com/vuln.xml" \\
           --output blindspots.csv

  # Delta run: only articles newer than a timestamp (epoch ms)
  %(prog)s --config config.yaml --newer-than 1758153600000

  # Only uncovered CVEs that actually have an exploit behind them
  %(prog)s --config config.yaml --exploited-only --json-output report.json

  # Inspect the raw detectedBy structure without running a report
  %(prog)s --inspect-detected-by CVE-2024-3400 CVE-2024-21412
""",
    )
    parser.add_argument("--config", help="YAML config file with stream_ids and settings")
    parser.add_argument("--stream-id", action="append", dest="stream_ids", default=[],
                        help="Stream ID to pull (repeatable: folders and feeds both)")
    parser.add_argument("--newer-than", type=int,
                        help="Only articles newer than this epoch-ms timestamp (delta runs)")
    parser.add_argument("--max-articles", type=int,
                        help="Stop after N articles per stream (testing safeguard)")
    parser.add_argument("--output", "-o", default="nessus_blindspots.csv",
                        help="CSV output path (default: nessus_blindspots.csv)")
    parser.add_argument("--json-output", help="Also write JSON to this path")
    parser.add_argument("--blind-spots-only", action="store_true",
                        help="Emit only the Blind spot bucket (every CVE with no "
                             "Nessus plugin)")
    parser.add_argument("--confirmed-only", action="store_true",
                        help="Narrow blind spots to those another scanner detects, "
                             "the strongest evidence the gap is real")
    parser.add_argument("--exploited-only", action="store_true",
                        help="Only CVEs with a known exploit or PoC")
    parser.add_argument("--include-rejected", action="store_true",
                        help="Keep Rejected / Likely Rejected CVE IDs (off by default)")
    parser.add_argument("--inspect-detected-by", nargs="+", metavar="CVE",
                        help="Print the raw detectedBy structure for sample CVEs and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run every stage but write no output files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    return parser.parse_args()


def inspect_detected_by(client: FeedlyClient, cve_ids: List[str]) -> None:
    """Print the raw detectedBy structure so the filter can be sanity-checked."""
    print("=" * 70)
    print("RAW detectedBy STRUCTURE")
    print("=" * 70)
    cards = client.entities_mget(cve_ids)
    found = {card_cve_id(c): c for c in cards}

    for cve_id in cve_ids:
        card = found.get(cve_id.upper())
        print(f"\n--- {cve_id.upper()}")
        if not card:
            print("    not found in Feedly")
            continue
        detected_by = card.get("detectedBy")
        print(f"    type       : {type(detected_by).__name__}")
        print(f"    entries    : {len(detected_by) if isinstance(detected_by, list) else 0}")
        print(f"    raw        : {json.dumps(detected_by)}")
        if isinstance(detected_by, list) and detected_by:
            print(f"    entry keys : {sorted(detected_by[0].keys()) if isinstance(detected_by[0], dict) else '-'}")
        coverage = classify_coverage(card)
        print(f"    -> bucket  : {coverage['bucket']}")
        print(f"    -> evidence: {coverage['evidence']}")
        print(f"    -> plugins : {coverage['plugin_ids']}")
        print(f"    -> others  : {coverage['other_scanners']}")
        print(f"    cveStatus  : {card.get('cveStatus')!r}  "
              f"exploit: {exploit_status(card)!r}")


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    global VERBOSE
    args = parse_args()
    VERBOSE = args.verbose

    if API_KEY == "APIKEYHERE":
        print("ERROR: no API token found. Set FEEDLY_TOKEN in your environment "
              "or add FEEDLY_API_KEY to a .env file.")
        return 1

    client = FeedlyClient(API_KEY)

    # Structure inspection mode: no report, just the raw field shape
    if args.inspect_detected_by:
        inspect_detected_by(client, args.inspect_detected_by)
        return 0

    # -- resolve streams ---------------------------------------------------
    config = load_config(args.config) if args.config else {}
    stream_ids: List[str] = list(args.stream_ids)
    for key in ("stream_ids", "folder_stream_ids", "feed_stream_ids"):
        for sid in config.get(key) or []:
            if sid not in stream_ids:
                stream_ids.append(sid)

    if not stream_ids:
        print("ERROR: no stream IDs. Pass --stream-id (repeatable) or --config.")
        return 1

    newer_than = args.newer_than or config.get("newer_than")
    exploited_only = args.exploited_only or bool(config.get("exploited_only"))
    include_rejected = args.include_rejected or bool(config.get("include_rejected"))

    print("=" * 70)
    print("FEEDLY -> NESSUS BLIND SPOT REPORT")
    print("=" * 70)
    print(f"  Streams          : {len(stream_ids)}")
    print(f"  newerThan        : {newer_than or '(full pull)'}")
    print(f"  Exploited only   : {exploited_only}")
    print(f"  Rejected CVEs    : {'kept' if include_rejected else 'filtered out'}")
    if args.dry_run:
        print("  DRY RUN          : no files will be written")

    # -- stage 1 -----------------------------------------------------------
    print("\n[1/5] Collecting articles")
    articles = collect_articles(client, stream_ids, newer_than, args.max_articles)
    print(f"\n  Total articles: {len(articles)}")
    if not articles:
        print("  Nothing to do. Check the stream IDs and newerThan window.")
        return 0

    # -- stage 2 -----------------------------------------------------------
    print("\n[2/5] Extracting CVE IDs")
    extraction_index = extract_all_cves(articles)
    via_entity = sum(1 for v in extraction_index.values() if "entity" in v["methods"])
    via_regex_only = sum(1 for v in extraction_index.values() if v["methods"] == {"regex"})
    print(f"  Unique CVEs        : {len(extraction_index)}")
    print(f"    entity-derived   : {via_entity}")
    print(f"    regex-only       : {via_regex_only}  (tagged in output for traceability)")
    if not extraction_index:
        print("  No CVEs found in these streams.")
        return 0

    # -- stage 3 -----------------------------------------------------------
    print("\n[3/5] Enriching via insight cards")
    cards, not_found = enrich_cves(client, list(extraction_index.keys()))
    print(f"  Cards retrieved    : {len(cards)}")
    if not_found:
        print(f"  Not found in Feedly: {len(not_found)} "
              f"({', '.join(not_found[:5])}{'...' if len(not_found) > 5 else ''})")

    # -- stage 4 -----------------------------------------------------------
    print("\n[4/5] Classifying Nessus coverage")
    rows: List[Dict[str, Any]] = []
    dropped_rejected = 0
    dropped_no_exploit = 0

    for cve_id, card in cards.items():
        status = str(card.get("cveStatus") or "").strip().lower()
        if not include_rejected and status in REJECTED_STATUSES:
            dropped_rejected += 1
            vlog(f"dropping {cve_id}: cveStatus={card.get('cveStatus')!r}")
            continue

        row = build_row(cve_id, card, extraction_index.get(cve_id, {}))

        if exploited_only and row["exploit_status"] == NO_EXPLOIT:
            dropped_no_exploit += 1
            continue

        rows.append(row)

    # CVEs seen in the streams that Feedly has no card for: coverage unknowable
    for cve_id in not_found:
        rows.append(build_unknown_row(cve_id, extraction_index.get(cve_id, {})))

    if args.blind_spots_only:
        before = len(rows)
        rows = [r for r in rows if r["coverage"] == BLIND_SPOT]
        print(f"  --blind-spots-only: kept {len(rows)} of {before} rows")

    if args.confirmed_only:
        before = len(rows)
        rows = [r for r in rows if r["evidence"] == EVIDENCE_OTHER_SCANNERS]
        print(f"  --confirmed-only: kept {len(rows)} of {before} rows")

    rows = sort_rows(rows)

    summary = {
        "articles": len(articles),
        "streams": stream_ids,
        "newer_than": newer_than,
        "cves_extracted": len(extraction_index),
        "via_entity": via_entity,
        "via_regex_only": via_regex_only,
        "cards": len(cards),
        "not_found": len(not_found),
        "not_found_ids": not_found,
        "dropped_rejected": dropped_rejected,
        "dropped_no_exploit": dropped_no_exploit,
        "covered": sum(1 for r in rows if r["coverage"] == COVERED),
        "blind_spot": sum(1 for r in rows if r["coverage"] == BLIND_SPOT),
        "blind_spot_confirmed": sum(1 for r in rows
                                    if r["evidence"] == EVIDENCE_OTHER_SCANNERS),
        "blind_spot_no_data": sum(1 for r in rows
                                  if r["evidence"] == EVIDENCE_NO_DATA),
        "unknown": sum(1 for r in rows if r["coverage"] == UNKNOWN),
    }

    # -- stage 5 -----------------------------------------------------------
    print("\n[5/5] Writing output")
    if args.dry_run:
        print("  (dry run: skipping file writes)")
    else:
        write_csv(rows, args.output)
        if args.json_output:
            write_json(rows, args.json_output, summary)

    print_summary(rows, summary)
    print(f"\n  {client.quota_summary()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
