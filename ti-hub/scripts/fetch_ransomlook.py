"""
fetch_ransomlook.py
Fetches ransomware group posts and market data from RansomLook API.
API key required — set RANSOMLOOK_API_KEY environment variable.
Falls back to partial data if no key available.
"""

import requests
import json
import time
import logging
import os
from datetime import datetime, timezone

BASE_URL = "https://www.ransomlook.io/api"
REQUEST_TIMEOUT = 20
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 0.5

logging.basicConfig(level=logging.INFO, format="%(asctime)s [RansomLook] %(message)s")
log = logging.getLogger(__name__)


def _get_headers() -> dict:
    api_key = os.environ.get("RANSOMLOOK_API_KEY", "")
    headers = {
        "User-Agent": "TheSixteenProject-TIHub/1.0",
        "Accept": "application/json"
    }
    if api_key:
        headers["Authorization"] = api_key
    return headers


def _has_api_key() -> bool:
    return bool(os.environ.get("RANSOMLOOK_API_KEY", "").strip())


def _get(endpoint: str, retries: int = MAX_RETRIES) -> dict | list | None:
    url = f"{BASE_URL}{endpoint}"
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=_get_headers())
            if resp.status_code == 403:
                log.warning("API key required or invalid for: " + endpoint)
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code
            log.warning(f"HTTP {code} on {url} (attempt {attempt+1})")
            if code == 429:
                time.sleep(10 * (attempt + 1))
            elif code in (401, 403):
                return None
        except requests.exceptions.RequestException as e:
            log.warning(f"Request error: {e} (attempt {attempt+1})")
            time.sleep(3 * (attempt + 1))
    return None


def fetch_groups() -> list[dict]:
    log.info("Fetching RansomLook groups...")
    raw = _get("/export/0")  # export database 0 = groups
    if not raw:
        log.warning("Export endpoint failed, trying individual group fallback...")
        return []

    groups = []
    if isinstance(raw, list):
        source_list = raw
    elif isinstance(raw, dict):
        source_list = list(raw.values()) if raw else []
    else:
        return []

    for item in source_list:
        if not isinstance(item, dict):
            continue

        name = item.get("name", item.get("group_name", ""))
        if not name:
            continue

        locations = []
        for loc in item.get("locations", []):
            if isinstance(loc, dict):
                locations.append({
                    "url": loc.get("fqdn", loc.get("url", "")),
                    "type": loc.get("type", "unknown"),
                    "available": loc.get("available", False),
                    "title": loc.get("title", "")
                })

        groups.append({
            "id": name.lower().replace(" ", "-"),
            "name": name,
            "is_raas": item.get("is_raas", False),
            "locations": locations[:10],
            "crypto": item.get("crypto", {}),
            "meta": item.get("meta", {}),
            "source": "ransomlook"
        })

    log.info(f"Done. Fetched {len(groups)} groups from RansomLook.")
    return groups


def fetch_posts(days: int = 30) -> list[dict]:
    if not _has_api_key():
        log.warning("No RANSOMLOOK_API_KEY set. Skipping posts fetch.")
        return []

    log.info(f"Fetching RansomLook posts (last {days} days)...")
    raw = _get(f"/posts?days={days}")
    if not raw:
        # Try export endpoint
        raw = _get("/export/2")

    if not raw:
        return []

    posts = []
    source_list = raw if isinstance(raw, list) else []

    for item in source_list:
        if not isinstance(item, dict):
            continue

        group = item.get("group_name", item.get("group", ""))
        victim = item.get("post_title", item.get("victim", ""))

        if not victim:
            continue

        posts.append({
            "id": f"rl-{group}-{victim[:20].lower().replace(' ', '-')}",
            "victim": victim[:200],
            "group": group,
            "group_id": group.lower().replace(" ", "-"),
            "published": item.get("discovered", item.get("published", "")),
            "description": (item.get("description") or "")[:300],
            "url": item.get("post_url", ""),
            "source": "ransomlook"
        })

    log.info(f"Done. Fetched {len(posts)} posts from RansomLook.")
    return posts


def fetch_markets() -> list[dict]:
    log.info("Fetching RansomLook markets...")
    raw = _get("/export/3")  # database 3 = markets
    if not raw:
        return []

    markets = []
    source_list = raw if isinstance(raw, list) else list(raw.values()) if isinstance(raw, dict) else []

    for item in source_list:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        if not name:
            continue
        markets.append({
            "name": name,
            "locations": item.get("locations", [])[:5],
            "source": "ransomlook"
        })

    log.info(f"Done. Fetched {len(markets)} markets.")
    return markets


def merge_with_ransomwarelive(rl_groups: list[dict], ransomlook_groups: list[dict]) -> list[dict]:
    """Merge RansomLook data into existing ransomware.live group records."""
    rl_index = {g["id"]: g for g in ransomlook_groups}

    for group in rl_groups:
        gid = group["id"]
        if gid in rl_index:
            extra = rl_index[gid]
            group["is_raas"] = extra.get("is_raas", False)
            group["crypto"] = extra.get("crypto", {})
            # Merge locations
            existing_urls = {l["url"] for l in group.get("locations", [])}
            for loc in extra.get("locations", []):
                if loc.get("url") and loc["url"] not in existing_urls:
                    group["locations"].append(loc)

    return rl_groups
