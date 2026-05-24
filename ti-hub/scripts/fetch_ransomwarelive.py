"""
fetch_ransomwarelive.py
Fetches ransomware groups and victim data from Ransomware.live API v2.
No authentication required for v2 endpoints.
"""

import requests
import json
import time
import logging
from datetime import datetime, timezone

BASE_URL = "https://api.ransomware.live/v2"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 0.5

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RansomLive] %(message)s")
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
            code = e.response.status_code
            log.warning(f"HTTP {code} on {url} (attempt {attempt+1})")
            if code == 429:
                time.sleep(10 * (attempt + 1))
            elif code == 404:
                return None
        except requests.exceptions.RequestException as e:
            log.warning(f"Request error: {e} (attempt {attempt+1})")
            time.sleep(3 * (attempt + 1))
    log.error(f"Failed after {retries} attempts: {url}")
    return None


def fetch_groups() -> list[dict]:
    log.info("Fetching ransomware groups...")
    raw = _get("/groups")
    if not raw:
        return []

    groups = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        name = item.get("name", "")
        if not name:
            continue

        # Fetch detail per group for TTPs and extra data
        detail = _get(f"/group/{name}")
        time.sleep(RATE_LIMIT_DELAY)

        ttps = []
        tools = []
        yara_rules = []
        locations = []

        if detail and isinstance(detail, dict):
            # TTPs (MITRE ATT&CK)
            raw_ttps = detail.get("ttps", [])
            if isinstance(raw_ttps, list):
                for ttp in raw_ttps:
                    if isinstance(ttp, dict):
                        ttps.append({
                            "tactic_id": ttp.get("tactic_id", ""),
                            "tactic_name": ttp.get("tactic_name", ""),
                            "technique_id": ttp.get("technique_id", ""),
                            "technique_name": ttp.get("technique_name", ""),
                            "details": ttp.get("technique_details", "")[:300]
                        })

            # Tools
            raw_tools = detail.get("tools", [])
            if isinstance(raw_tools, list):
                tools = [t for t in raw_tools if isinstance(t, str)]

            # Locations (Tor sites)
            raw_locs = detail.get("locations", item.get("locations", []))
            if isinstance(raw_locs, list):
                for loc in raw_locs:
                    if isinstance(loc, dict):
                        locations.append({
                            "url": loc.get("url", loc.get("fqdn", "")),
                            "type": loc.get("type", "DLS"),
                            "available": loc.get("available", False)
                        })

            # YARA
            raw_yara = detail.get("yara", [])
            if isinstance(raw_yara, list):
                yara_rules = raw_yara[:5]

        elif isinstance(item.get("locations"), list):
            for loc in item["locations"]:
                if isinstance(loc, dict):
                    locations.append({
                        "url": loc.get("url", loc.get("fqdn", "")),
                        "type": loc.get("type", "DLS"),
                        "available": loc.get("available", False)
                    })

        groups.append({
            "id": name.lower().replace(" ", "-"),
            "name": name,
            "description": (item.get("description") or "")[:1000],
            "status": _infer_status(item, detail),
            "first_seen": item.get("added_date", ""),
            "locations": locations[:10],
            "tools": tools[:20],
            "ttps": ttps,
            "yara_rules": yara_rules,
            "victim_count": 0,  # will be enriched after victim fetch
            "updated": datetime.now(timezone.utc).isoformat()
        })

    log.info(f"Done. Fetched {len(groups)} ransomware groups.")
    return groups


def _infer_status(item: dict, detail: dict | None) -> str:
    if detail:
        locs = detail.get("locations", [])
        if isinstance(locs, list) and locs:
            available = [l for l in locs if isinstance(l, dict) and l.get("available")]
            if available:
                return "active"
            return "inactive"
    return "unknown"


def fetch_victims() -> list[dict]:
    log.info("Fetching all victims (cyberattacks)...")
    raw = _get("/allcyberattacks")
    if not raw:
        log.warning("allcyberattacks failed, trying recentvictims...")
        raw = _get("/recentvictims")

    if not raw:
        return []

    victims = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        group = item.get("group", "unknown")
        victim_name = item.get("victim", item.get("post_title", ""))
        if not victim_name:
            continue

        # Infostealer data
        infostealer = {}
        raw_is = item.get("infostealer", {})
        if isinstance(raw_is, dict):
            infostealer = {
                "employees": raw_is.get("employees", 0),
                "users": raw_is.get("users", 0),
                "stealers": raw_is.get("stealers", {}) if isinstance(raw_is.get("stealers"), dict) else {}
            }

        victims.append({
            "id": f"{group}-{victim_name[:30].lower().replace(' ', '-').replace('/', '-')}",
            "victim": victim_name[:200],
            "domain": (item.get("domain") or "")[:100],
            "group": group,
            "group_id": group.lower().replace(" ", "-"),
            "country": (item.get("country") or "").upper()[:2],
            "sector": item.get("activity", item.get("sector", "Unknown")),
            "attack_date": item.get("attackdate", item.get("date", "")),
            "discovered": item.get("discovered", ""),
            "description": (item.get("description") or "")[:500],
            "claim_url": item.get("claim_url", ""),
            "infostealer": infostealer,
            "source": "ransomware.live"
        })

    log.info(f"Done. Fetched {len(victims)} victims.")
    return victims


def enrich_group_victim_counts(groups: list[dict], victims: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for v in victims:
        gid = v.get("group_id", "")
        if gid:
            counts[gid] = counts.get(gid, 0) + 1

    for g in groups:
        g["victim_count"] = counts.get(g["id"], 0)
    return groups
