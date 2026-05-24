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


def _parse_rl_group_detail(name: str, detail: dict) -> dict:
    """Parse /group/{name} response into normalized group dict."""
    locations = []
    for loc in (detail.get("locations") or []):
        if isinstance(loc, dict):
            locations.append({
                "url": loc.get("fqdn", loc.get("url", "")),
                "type": loc.get("type", "unknown"),
                "available": loc.get("available", False),
                "title": loc.get("title", "")
            })

    affiliates = detail.get("affiliates") or []
    if isinstance(affiliates, str):
        affiliates = [a.strip() for a in affiliates.split(",") if a.strip()]

    return {
        "id": name.lower().replace(" ", "-"),
        "name": name,
        "is_raas": bool(detail.get("raas", False)),
        "locations": locations[:10],
        "affiliates": list(affiliates)[:20],
        "jabber": (detail.get("jabber") or "")[:200],
        "mail": (detail.get("mail") or "")[:200],
        "telegram": (detail.get("telegram") or "")[:200],
        "profile": (detail.get("profile") or "")[:800],
        "captcha": bool(detail.get("captcha", False)),
        "source": "ransomlook"
    }


def fetch_groups() -> list[dict]:
    log.info("Fetching RansomLook groups...")
    # /groups returns list of group name strings; /export/0 requires auth
    raw = _get("/groups")
    if not raw:
        log.warning("RansomLook /groups failed — skipping.")
        return []

    groups = []

    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                name = item.strip()
                if name:
                    groups.append({
                        "id": name.lower().replace(" ", "-"),
                        "name": name,
                        "is_raas": False,
                        "locations": [],
                        "affiliates": [],
                        "source": "ransomlook"
                    })
            elif isinstance(item, dict):
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
                        })
                groups.append({
                    "id": name.lower().replace(" ", "-"),
                    "name": name,
                    "is_raas": bool(item.get("raas", item.get("is_raas", False))),
                    "locations": locations[:10],
                    "affiliates": list(item.get("affiliates", []))[:20],
                    "profile": (item.get("profile") or "")[:800],
                    "source": "ransomlook"
                })
    elif isinstance(raw, dict):
        source_list = raw.get("groups", raw.get("data", list(raw.values())))
        if isinstance(source_list, list):
            for item in source_list:
                if isinstance(item, dict):
                    name = item.get("name", "")
                    if name:
                        groups.append({
                            "id": name.lower().replace(" ", "-"),
                            "name": name,
                            "is_raas": bool(item.get("raas", False)),
                            "source": "ransomlook"
                        })

    log.info(f"Done. Fetched {len(groups)} groups from RansomLook.")
    return groups


def fetch_stats() -> dict:
    """Fetch global statistics from RansomLook /stats."""
    log.info("Fetching RansomLook global stats...")
    raw = _get("/stats")
    if isinstance(raw, dict):
        return {
            "groups": int(raw.get("groups") or 0),
            "posts_total": int(raw.get("posts_total") or 0),
            "posts_24h": int(raw.get("posts_24h") or 0),
            "posts_month": int(raw.get("posts_month") or 0),
            "posts_90d": int(raw.get("posts_90d") or 0),
            "posts_year": int(raw.get("posts_year") or 0),
            "markets": int(raw.get("markets") or 0),
        }
    return {}


def fetch_recent(limit: int = 50) -> list[dict]:
    """Fetch recent victim posts from RansomLook /recent."""
    log.info("Fetching RansomLook recent posts...")
    raw = _get("/recent")
    if not raw or not isinstance(raw, list):
        return []

    result = []
    for item in raw[:limit]:
        if not isinstance(item, dict):
            continue
        result.append({
            "victim": (item.get("post_title") or "")[:200],
            "group": (item.get("group_name") or "")[:100],
            "published": item.get("discovered", ""),
            "description": (item.get("description") or "")[:400],
            "link": (item.get("link") or "")[:500],
            "source": "ransomlook"
        })

    log.info(f"Fetched {len(result)} recent posts from RansomLook.")
    return result


def fetch_posts(days: int = 30) -> list[dict]:
    if not _has_api_key():
        log.warning("No RANSOMLOOK_API_KEY set. Skipping posts fetch.")
        return []

    log.info(f"Fetching RansomLook posts (last {days} days)...")
    raw = _get(f"/posts?days={days}")
    if not raw:
        raw = _get("/export/2")
    if not raw:
        return []

    posts = []
    for item in (raw if isinstance(raw, list) else []):
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


def merge_with_ransomwarelive(rl_groups: list[dict], ransomlook_groups: list[dict]) -> list[dict]:
    """Merge RansomLook data into existing ransomware.live group records."""
    rl_index = {g["id"]: g for g in ransomlook_groups}

    for group in rl_groups:
        gid = group["id"]
        if gid in rl_index:
            extra = rl_index[gid]
            group["is_raas"] = extra.get("is_raas", False)
            if extra.get("affiliates"):
                group["affiliates"] = extra["affiliates"]
            if extra.get("jabber"):
                group["jabber"] = extra["jabber"]
            if extra.get("mail"):
                group["mail"] = extra["mail"]
            if extra.get("telegram"):
                group["telegram"] = extra["telegram"]
            if extra.get("profile") and not group.get("description"):
                group["description"] = extra["profile"]
            # Merge extra locations (Tor sites from RansomLook)
            existing_urls = {l.get("url", "") for l in group.get("locations", [])}
            for loc in extra.get("locations", []):
                if loc.get("url") and loc["url"] not in existing_urls:
                    group.setdefault("locations", []).append(loc)

    return rl_groups
