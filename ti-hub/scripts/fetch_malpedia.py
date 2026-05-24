"""
fetch_malpedia.py
Fetches malware families and threat actors from Malpedia API.
No authentication required. Bulk endpoints return all data in 2 requests.
"""

import requests
import json
import time
import logging
from datetime import datetime, timezone

BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de/api"
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Malpedia] %(message)s")
log = logging.getLogger(__name__)


def _get(endpoint: str, retries: int = MAX_RETRIES) -> dict | list | None:
    url = f"{BASE_URL}{endpoint}"
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={
                "User-Agent": "TheSixteenProject-TIHub/1.0",
                "Accept": "application/json"
            })
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            log.warning(f"HTTP {e.response.status_code} on {url} (attempt {attempt+1})")
            if e.response.status_code == 429:
                time.sleep(5 * (attempt + 1))
        except requests.exceptions.RequestException as e:
            log.warning(f"Request error on {url}: {e} (attempt {attempt+1})")
            time.sleep(2 * (attempt + 1))
    log.error(f"Failed after {retries} attempts: {url}")
    return None


def _parse_platform(malpedia_name: str) -> list[str]:
    prefix_map = {
        "win": "Windows", "elf": "Linux", "apk": "Android",
        "aix": "AIX/Unix", "osx": "macOS", "ios": "iOS",
        "js": "JavaScript", "py": "Python", "ps1": "PowerShell",
        "vbs": "VBScript", "jar": "Java", "doc": "Office Document",
        "pdf": "PDF", "php": "PHP", "sh": "Shell",
    }
    parts = malpedia_name.split(".")
    if parts:
        return [prefix_map.get(parts[0].lower(), parts[0].upper())]
    return ["Unknown"]


def _infer_type(malpedia_name: str, description: str, alt_names: list) -> str:
    combined = (malpedia_name + " " + description + " " + " ".join(alt_names)).lower()
    type_keywords = {
        "ransomware": ["ransom", "encrypt", "locker"],
        "rat":        ["rat", "remote access trojan", "remote administration"],
        "banker":     ["banker", "banking"],
        "stealer":    ["stealer", "infostealer", "credential"],
        "loader":     ["loader", "dropper"],
        "backdoor":   ["backdoor", "back door"],
        "wiper":      ["wiper", "destruct", "destroy disk"],
        "rootkit":    ["rootkit"],
        "botnet":     ["botnet", "ddos"],
        "spyware":    ["spyware", "keylog"],
        "worm":       ["worm", "self-replicat"],
        "tool":       ["tool", "scanner", "framework", "utility", "post-exploit"],
    }
    for t, keywords in type_keywords.items():
        if any(kw in combined for kw in keywords):
            return t
    return "malware"


def fetch_families() -> list[dict]:
    """Fetch all malware families in one bulk request (3700+ entries)."""
    log.info("Fetching all malware families (bulk)...")
    raw = _get("/get/families")

    if not raw or not isinstance(raw, dict):
        log.error("Unexpected response format for families")
        return []

    families = []
    now = datetime.now(timezone.utc).isoformat()

    for malpedia_name, detail in raw.items():
        if not isinstance(detail, dict):
            continue

        alt_names = detail.get("alt_names", [])
        if isinstance(alt_names, str):
            alt_names = [alt_names] if alt_names else []
        alt_names = [str(a) for a in alt_names if a]

        # Attribution (actors)
        attribution = detail.get("attribution", [])
        actor_ids = []
        if isinstance(attribution, list):
            for a in attribution:
                if isinstance(a, str) and a:
                    actor_ids.append(a)
                elif isinstance(a, dict) and a.get("actor_names"):
                    actor_ids.extend(a["actor_names"])

        # Reference URLs
        urls = detail.get("urls", [])
        refs = [u for u in urls if isinstance(u, str) and u.startswith("http")][:20]

        # Description from library_entries if empty
        description = str(detail.get("description") or "")
        if not description and detail.get("library_entries"):
            entries = detail["library_entries"]
            if isinstance(entries, list) and entries:
                first = entries[0]
                if isinstance(first, dict):
                    description = str(first.get("description") or "")[:500]

        families.append({
            "id":          malpedia_name,
            "name":        str(detail.get("common_name") or
                              malpedia_name.split(".")[-1].replace("_", " ").title()),
            "aliases":     alt_names[:15],
            "platform":    _parse_platform(malpedia_name),
            "type":        _infer_type(malpedia_name, description, alt_names),
            "description": description[:1000],
            "actors":      list(dict.fromkeys(actor_ids))[:10],
            "references":  refs,
            "uuid":        str(detail.get("uuid") or ""),
            "updated":     str(detail.get("updated") or now)
        })

    log.info(f"Done. Parsed {len(families)} malware families.")
    return families


def fetch_actors() -> list[dict]:
    """Fetch all threat actors in one bulk request (994+ entries)."""
    log.info("Fetching all threat actors (bulk)...")
    raw = _get("/get/actors")

    if not raw or not isinstance(raw, dict):
        log.error("Unexpected response format for actors")
        return []

    actors = []
    now = datetime.now(timezone.utc).isoformat()

    for actor_name, detail in raw.items():
        if not isinstance(detail, dict):
            continue

        # Aliases from meta or top-level
        meta = detail.get("meta", {}) or {}
        synonyms = meta.get("synonyms", []) or []
        if isinstance(synonyms, str):
            synonyms = [synonyms] if synonyms else []
        alt_names = [str(s) for s in synonyms if s]

        # Country from meta
        country = str(meta.get("country", "Unknown") or "Unknown")
        if len(country) == 2:
            # ISO2 code — keep as is, frontend will expand
            pass

        # Malware families used (from families key in detail)
        malware_used = []
        fams = detail.get("families", []) or []
        if isinstance(fams, list):
            for f in fams:
                if isinstance(f, str) and f:
                    malware_used.append(f)
                elif isinstance(f, dict):
                    fn = f.get("malpedia_name") or f.get("name") or ""
                    if fn:
                        malware_used.append(str(fn))

        # References from meta.refs
        refs = meta.get("refs", []) or []
        refs = [r for r in refs if isinstance(r, str) and r.startswith("http")][:20]

        # Description
        description = str(detail.get("description") or "")[:1000]

        # Extra fields from CFR/meta
        suspected_victims   = meta.get("cfr-suspected-victims", []) or []
        target_categories   = meta.get("cfr-target-category", []) or []
        incident_types      = meta.get("cfr-type-of-incident", []) or []
        state_sponsor       = meta.get("cfr-suspected-state-sponsor", "") or ""
        attribution_conf    = meta.get("attribution-confidence", "") or ""

        # Collect alternative vendor names (e.g. "origin:APT-C-26": "QiAnXin")
        vendor_names = {}
        for k, v in meta.items():
            if k.startswith("origin:") and isinstance(v, str):
                vendor_names[k[7:]] = v  # strip "origin:" prefix

        actors.append({
            "id":                actor_name,
            "name":              str(detail.get("common_name") or actor_name),
            "aliases":           alt_names[:30],
            "description":       description,
            "malware":           [],          # populated later via cross-reference
            "country":           country,
            "country_iso":       country if len(country) == 2 else "??",
            "state_sponsor":     state_sponsor,
            "target_categories": list(target_categories)[:10],
            "incident_types":    list(incident_types)[:10],
            "suspected_victims": list(suspected_victims)[:20],
            "vendor_names":      vendor_names,
            "attribution_confidence": attribution_conf,
            "references":        refs,
            "updated":           now
        })

    log.info(f"Done. Parsed {len(actors)} threat actors.")
    return actors
