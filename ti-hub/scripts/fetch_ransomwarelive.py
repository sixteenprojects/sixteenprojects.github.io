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


def _parse_victim_item(item: dict) -> dict | None:
    """Parse a raw victim/cyberattack record into normalized format."""
    if not isinstance(item, dict):
        return None
    group = item.get("group", "unknown")
    victim_name = item.get("victim", item.get("post_title", ""))
    if not victim_name:
        return None

    infostealer = {}
    raw_is = item.get("infostealer", {})
    if isinstance(raw_is, dict):
        infostealer = {
            "employees": int(raw_is.get("employees") or 0),
            "users": int(raw_is.get("users") or 0),
            "stealers": raw_is.get("stealers", {}) if isinstance(raw_is.get("stealers"), dict) else {}
        }

    return {
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
        "claim_url": (item.get("claim_url") or "")[:500],
        "url": (item.get("url") or "")[:500],
        "press": (item.get("press") or "")[:1000],
        "data_size": str(item.get("data_size") or ""),
        "ransom": str(item.get("ransom") or ""),
        "screenshot": (item.get("screenshot") or "")[:500],
        "infostealer": infostealer,
        "source": "ransomware.live"
    }


def fetch_victims() -> list[dict]:
    log.info("Fetching all victims (cyberattacks)...")

    # Try /allcyberattacks first (returns full dataset when working)
    raw_all = _get("/allcyberattacks")

    # Also fetch year-by-year to capture historical data not in /allcyberattacks
    current_year = datetime.now(timezone.utc).year
    raw_yearly: list[dict] = []
    for year in range(2019, current_year + 1):
        year_data = _get(f"/victims/{year}")
        if year_data and isinstance(year_data, list):
            log.info(f"  Year {year}: {len(year_data)} victims")
            raw_yearly.extend(year_data)
        time.sleep(RATE_LIMIT_DELAY)

    # Merge: start with yearly (historical), add anything from allcyberattacks not already covered
    seen_keys: set[str] = set()
    merged: list[dict] = []

    def _add_raw(items: list) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            key = f"{item.get('group','')}:{item.get('victim', item.get('post_title',''))}"
            if key and key not in seen_keys:
                seen_keys.add(key)
                merged.append(item)

    _add_raw(raw_yearly)
    if raw_all and isinstance(raw_all, list):
        _add_raw(raw_all)

    if not merged:
        log.warning("All endpoints empty, trying recentvictims fallback...")
        fallback = _get("/recentvictims")
        if fallback and isinstance(fallback, list):
            merged = fallback

    if not merged:
        return []

    victims = []
    for item in merged:
        parsed = _parse_victim_item(item)
        if parsed:
            victims.append(parsed)

    log.info(f"Done. Fetched {len(victims)} victims total "
             f"({len(raw_yearly)} from yearly, "
             f"{len(raw_all) if raw_all else 0} from allcyberattacks).")
    return victims


def fetch_sectors() -> dict:
    """Fetch victim count by sector from ransomware.live /v2/sectors."""
    log.info("Fetching sector statistics...")
    raw = _get("/sectors")
    if isinstance(raw, dict) and raw:
        log.info(f"Fetched {len(raw)} sectors.")
        return dict(sorted(raw.items(), key=lambda x: x[1], reverse=True))
    return {}


def fetch_recent_attacks() -> list[dict]:
    """Fetch recent attacks with AI-generated summaries from /v2/recentcyberattacks."""
    log.info("Fetching recent cyber attacks...")
    raw = _get("/recentcyberattacks")
    if not raw or not isinstance(raw, list):
        return []

    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        result.append({
            "victim": (item.get("victim") or item.get("title") or "")[:200],
            "group": (item.get("claim_gang") or item.get("group") or "")[:100],
            "country": (item.get("country") or "")[:2].upper(),
            "domain": (item.get("domain") or "")[:100],
            "date": item.get("date") or item.get("added") or "",
            "summary": (item.get("summary") or "")[:600],
            "url": (item.get("url") or item.get("link") or "")[:500],
            "claim_url": (item.get("claim_url") or "")[:500],
            "has_infostealer": bool(item.get("has_infostealer_info")),
            "infostealer_data": item.get("infostealer_data") if isinstance(item.get("infostealer_data"), dict) else {},
            "source": "ransomware.live"
        })

    log.info(f"Fetched {len(result)} recent attacks.")
    return result


def enrich_group_victim_counts(groups: list[dict], victims: list[dict]) -> list[dict]:
    counts: dict[str, int] = {}
    for v in victims:
        gid = v.get("group_id", "")
        if gid:
            counts[gid] = counts.get(gid, 0) + 1

    for g in groups:
        g["victim_count"] = counts.get(g["id"], 0)
    return groups
