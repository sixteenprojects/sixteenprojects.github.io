"""
fetch_otx.py
Fetches IOC pulses from OTX AlienVault for known threat actors.
Output: data/ioc.json  — actor_id → { pulses, indicators, updated }

Usage:
    python fetch_otx.py [--limit 30] [--key YOUR_API_KEY]

API key (optional but recommended — raises rate limit from 10 to 1000 req/min):
    Set env variable OTX_API_KEY  OR  pass --key flag.
    Create a free key at: https://otx.alienvault.com/accounts/register
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

DATA_DIR = Path(__file__).parent.parent / "data"
OTX_BASE = "https://otx.alienvault.com/api/v1"
DEFAULT_PULSE_LIMIT = 20  # pulses per actor query
RATE_SLEEP = 6.5          # seconds between requests (10 req/min without key)
RATE_SLEEP_AUTH = 0.2     # seconds between requests with key

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OTX] %(message)s")
log = logging.getLogger(__name__)

# ── Indicator type normalisation ──────────────────────────────────────────────
TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "md5", "FileHash-SHA256": "sha256",
    "FileHash-SHA1": "sha1",
    "email": "email", "YARA": "yara",
    "CVE": "cve",
}


def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "TheSixteenProject-TIHub/1.0",
        "Accept": "application/json",
    })
    if api_key:
        s.headers["X-OTX-API-KEY"] = api_key
    return s


def search_actor(session: requests.Session, query: str, limit: int, rate_sleep: float) -> dict | None:
    """Search OTX pulses for a given actor name.  Returns raw API response or None."""
    url = f"{OTX_BASE}/search/pulses"
    params = {
        "q": query,
        "sort": "-modified",
        "limit": limit,
        "page": 1,
    }
    try:
        resp = session.get(url, params=params, timeout=20)
        if resp.status_code == 401:
            log.error("OTX 401 Unauthorised — check your API key")
            return None
        if resp.status_code == 429:
            log.warning("Rate limited — sleeping 60s")
            time.sleep(60)
            resp = session.get(url, params=params, timeout=20)
        resp.raise_for_status()
        time.sleep(rate_sleep)
        return resp.json()
    except requests.exceptions.ConnectionError:
        log.warning(f"Connection error for query '{query}'")
        return None
    except Exception as e:
        log.warning(f"Request error for '{query}': {e}")
        return None


def _parse_pulses(raw: dict, limit_indicators: int = 200) -> tuple[list, dict]:
    """Extract pulse summaries and deduplicated indicators from raw API response."""
    pulses_summary = []
    indicators: dict[str, list] = {k: [] for k in ["ip","domain","url","md5","sha256","sha1","email","cve","yara"]}
    seen: dict[str, set] = {k: set() for k in indicators}

    for pulse in raw.get("results", []):
        pulses_summary.append({
            "id":               pulse.get("id", ""),
            "name":             pulse.get("name", ""),
            "created":          pulse.get("created", "")[:10],
            "modified":         pulse.get("modified", "")[:10],
            "author":           pulse.get("author_name", ""),
            "tags":             pulse.get("tags", [])[:10],
            "indicators_count": pulse.get("indicators_count", 0),
            "references":       pulse.get("references", [])[:5],
        })

        for ind in pulse.get("indicators", []):
            itype = TYPE_MAP.get(ind.get("type", ""), "")
            val   = (ind.get("indicator") or "").strip()
            if not itype or not val:
                continue
            bucket = indicators[itype]
            if val not in seen[itype] and len(bucket) < limit_indicators:
                seen[itype].add(val)
                bucket.append(val)

    return pulses_summary, indicators


def build_search_queries(actor: dict) -> list[str]:
    """Generate search queries for an actor using name + key aliases."""
    queries = []
    name = actor.get("name") or ""
    if name:
        queries.append(name)

    for alias in (actor.get("aliases") or [])[:4]:
        if alias and alias.lower() != name.lower():
            queries.append(alias)

    return list(dict.fromkeys(queries))  # deduplicate, preserve order


def _merge_indicators(base: dict, extra: dict) -> dict:
    """Merge two indicator dicts, deduplicating each list."""
    for k, vals in extra.items():
        if k not in base:
            base[k] = []
        existing = set(base[k])
        for v in vals:
            if v not in existing and len(base[k]) < 300:
                existing.add(v)
                base[k].append(v)
    return base


def fetch_actor_iocs(
    session: requests.Session,
    actor: dict,
    pulse_limit: int,
    rate_sleep: float,
    max_queries: int = 2,
) -> dict | None:
    """Fetch and merge IOCs for a single actor across its top name+aliases."""
    queries = build_search_queries(actor)[:max_queries]
    if not queries:
        return None

    all_pulses: list = []
    all_indicators: dict = {k: [] for k in ["ip","domain","url","md5","sha256","sha1","email","cve","yara"]}
    seen_pulse_ids: set = set()

    for q in queries:
        log.info(f"  Querying OTX: {q!r}")
        raw = search_actor(session, q, pulse_limit, rate_sleep)
        if not raw:
            continue

        pulses, indicators = _parse_pulses(raw)

        for p in pulses:
            if p["id"] not in seen_pulse_ids:
                seen_pulse_ids.add(p["id"])
                all_pulses.append(p)

        all_indicators = _merge_indicators(all_indicators, indicators)

    if not all_pulses and not any(all_indicators.values()):
        return None

    # Trim empty indicator lists
    all_indicators = {k: v for k, v in all_indicators.items() if v}

    total_iocs = sum(len(v) for v in all_indicators.values())
    log.info(f"  → {len(all_pulses)} pulses, {total_iocs} IOCs")

    return {
        "pulses":     all_pulses[:50],
        "indicators": all_indicators,
        "updated":    datetime.now(timezone.utc).isoformat(),
    }


def run(api_key: str = "", pulse_limit: int = DEFAULT_PULSE_LIMIT) -> None:
    api_key = api_key or os.environ.get("OTX_API_KEY", "")
    rate_sleep = RATE_SLEEP_AUTH if api_key else RATE_SLEEP

    if api_key:
        log.info("OTX API key detected — using authenticated mode (high rate limit)")
    else:
        log.warning(
            "No OTX_API_KEY set — using public mode (10 req/min). "
            "Get a free key at https://otx.alienvault.com/accounts/register"
        )

    # Load actors from actors.json
    actors_path = DATA_DIR / "actors.json"
    if not actors_path.exists():
        log.error(f"actors.json not found at {actors_path}. Run fetch_all.py first.")
        return

    with open(actors_path, encoding="utf-8") as f:
        actors: list[dict] = json.load(f)

    # Load existing ioc.json to resume/update incrementally
    ioc_path = DATA_DIR / "ioc.json"
    existing: dict = {}
    if ioc_path.exists():
        try:
            with open(ioc_path, encoding="utf-8") as f:
                existing = json.load(f)
            log.info(f"Loaded existing ioc.json with {len(existing)} actor entries")
        except Exception:
            pass

    session = _session(api_key)

    # Prioritise actors with descriptions or more malware references
    priority = sorted(
        actors,
        key=lambda a: (
            bool(a.get("description")),
            len(a.get("malware") or []),
        ),
        reverse=True,
    )

    ioc_data = dict(existing)
    updated_count = 0

    log.info(f"Starting OTX fetch for {len(priority)} actors...")
    for i, actor in enumerate(priority):
        actor_id = actor.get("id", "")
        if not actor_id:
            continue

        log.info(f"[{i+1}/{len(priority)}] {actor_id}")
        result = fetch_actor_iocs(session, actor, pulse_limit, rate_sleep)

        if result:
            ioc_data[actor_id] = result
            updated_count += 1
        else:
            log.info(f"  → No OTX data found for {actor_id}")

        # Save incrementally every 10 actors so we don't lose progress
        if (i + 1) % 10 == 0:
            _write(ioc_path, ioc_data)
            log.info(f"Progress saved: {updated_count} actors with IOCs")

    _write(ioc_path, ioc_data)
    log.info(f"Done. {updated_count}/{len(priority)} actors have OTX IOC data.")
    log.info(f"Output: {ioc_path} ({ioc_path.stat().st_size // 1024} KB)")


def _write(path: Path, data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    key = ""
    limit = DEFAULT_PULSE_LIMIT

    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--key" and i + 1 < len(args):
            key = args[i + 1]
        elif arg == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                pass

    run(api_key=key, pulse_limit=limit)
