"""
fetch_otx.py — OTX AlienVault comprehensive intelligence fetch

Modes (combinable):
  (default)     Incremental: last 24h pulses → full indicators → map to actors
  --full        Full actor search: query each actor by name (slow, one-time)
  --groups      Fetch curated OTX group feeds
  --hours N     Incremental window in hours (default: 26)
  --limit N     Pulses per actor in full mode (default: 20)

Output: data/ioc.json
  {
    "actors": { actor_id: { pulses, indicators, updated } },
    "groups": { group_id: { name, pulses, updated } },
    "feed":   { updated, since, ip, domain, url, md5, sha256 },
    "meta":   { last_incremental, last_full, actor_coverage, group_count }
  }
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Install requests: pip install requests")

DATA_DIR      = Path(__file__).parent.parent / "data"
OTX_BASE      = "https://otx.alienvault.com/api/v1"
SLEEP_AUTH    = 0.25   # seconds between requests with API key
SLEEP_NOAUTH  = 6.5    # seconds without key
MAX_IND_PULSE = 300    # max indicator values stored per actor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OTX] %(message)s")
log = logging.getLogger("OTX")

TYPE_MAP = {
    "IPv4": "ip", "IPv6": "ip",
    "domain": "domain", "hostname": "domain",
    "URL": "url",
    "FileHash-MD5": "md5", "FileHash-SHA256": "sha256",
    "FileHash-SHA1": "sha1",
    "email": "email", "YARA": "yara", "CVE": "cve",
}

# Curated OTX groups — id confirmed from web UI
KNOWN_GROUPS = [
    (51,  "Ransomware Threat Intelligence"),
    (52,  "Malware Threat Intelligence"),
    (56,  "Linux Malware"),
    (100, "APT & Targeted Attacks"),
    (85,  "Phishing & Social Engineering"),
    (88,  "Banking Trojans & Financial Threats"),
]


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "TheSixteenProject-TIHub/2.0",
        "Accept":     "application/json",
    })
    if api_key:
        s.headers["X-OTX-API-KEY"] = api_key
    return s


def _get(session: requests.Session, url: str, params: dict, sleep: float) -> dict | None:
    for attempt in range(2):
        try:
            r = session.get(url, params=params, timeout=15)
            if r.status_code == 401:
                log.error("OTX 401 — invalid or missing API key")
                return None
            if r.status_code == 404:
                return None
            if r.status_code == 429:
                log.warning("Rate limited — sleeping 60s")
                time.sleep(60)
                continue
            r.raise_for_status()
            time.sleep(sleep)
            return r.json()
        except requests.exceptions.Timeout:
            log.warning(f"Timeout: {url}")
            return None
        except Exception as e:
            log.warning(f"Request error {url}: {e}")
            return None
    return None


# ── Indicator helpers ──────────────────────────────────────────────────────────

def _empty_ind() -> dict:
    return {k: [] for k in ["ip", "domain", "url", "md5", "sha256", "sha1", "email", "cve", "yara"]}


def _merge_ind(base: dict, raw_list: list) -> dict:
    seen = {k: set(v) for k, v in base.items()}
    for item in raw_list:
        t = TYPE_MAP.get(item.get("type", ""), "")
        v = (item.get("indicator") or "").strip()
        if not t or not v:
            continue
        bucket = base.setdefault(t, [])
        if v not in seen.get(t, set()) and len(bucket) < MAX_IND_PULSE:
            bucket.append(v)
            seen.setdefault(t, set()).add(v)
    return base


def _pulse_meta(p: dict) -> dict:
    return {
        "id":               p.get("id", ""),
        "name":             p.get("name", ""),
        "created":          (p.get("created") or "")[:10],
        "modified":         (p.get("modified") or "")[:10],
        "author":           p.get("author_name", ""),
        "tags":             (p.get("tags") or [])[:8],
        "indicators_count": p.get("indicators_count", 0),
        "references":       (p.get("references") or [])[:3],
    }


def _fetch_pulse_indicators(session: requests.Session, pulse_id: str, sleep: float) -> list:
    """Fetch indicator values for a single pulse (paginated)."""
    all_items = []
    page = 1
    while page <= 5:  # max 2500 indicators
        data = _get(session, f"{OTX_BASE}/pulses/{pulse_id}/indicators",
                    {"limit": 500, "page": page}, sleep)
        if not data:
            break
        results = data.get("results", [])
        all_items.extend(results)
        if not data.get("next"):
            break
        page += 1
    return all_items


# ── Actor index for local matching ─────────────────────────────────────────────

def _build_actor_index(actors: list) -> dict:
    """Build {lowercase_name: actor_id} from actors + aliases."""
    index = {}
    for a in actors:
        aid = a.get("id", "")
        if not aid:
            continue
        names = [a.get("name", "")] + (a.get("aliases") or [])
        for n in names:
            if n and len(n) >= 4:
                index[n.lower()] = aid
    return index


def _match_pulse_actors(pulse: dict, actor_index: dict) -> list:
    """Return actor_ids whose name/alias appears in this pulse's text."""
    text = " ".join(filter(None, [
        pulse.get("name", ""),
        " ".join(pulse.get("tags") or []),
        pulse.get("description", ""),
    ])).lower()
    matched = set()
    for name, aid in actor_index.items():
        if name in text:
            matched.add(aid)
    return list(matched)


# ── IO ─────────────────────────────────────────────────────────────────────────

def _load_ioc(path: Path) -> dict:
    _default = {"actors": {}, "groups": {}, "feed": {}, "meta": {}}
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return _default
            if "actors" not in raw:
                # Migrate old flat format (actor_id keys at top level)
                return {"actors": raw, "groups": {}, "feed": {}, "meta": {}}
            # Ensure all expected top-level keys exist
            for k, v in _default.items():
                raw.setdefault(k, v)
            return raw
        except Exception:
            pass
    return _default


def _write(path: Path, data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )


# ── Mode: full actor search ────────────────────────────────────────────────────

def run_full(session: requests.Session, sleep: float, actors: list,
             ioc_data: dict, pulse_limit: int = 20) -> None:
    """
    Search OTX per actor by name + top aliases. Stores pulse metadata only.

    Supports checkpoint/resume: actors already marked with 'full_searched_at'
    are skipped, so partial runs can be continued across multiple workflow runs.
    Save progress every 10 actors so GitHub Actions can commit partial results.
    """
    priority = sorted(
        actors,
        key=lambda a: (bool(a.get("description")), len(a.get("malware") or [])),
        reverse=True,
    )

    # Resume: skip actors already processed in a previous run
    remaining = [a for a in priority
                 if not ioc_data["actors"].get(a.get("id", ""), {}).get("full_searched_at")]
    done_count = len(priority) - len(remaining)

    log.info(f"Full actor search: {len(remaining)} remaining / {len(priority)} total "
             f"({done_count} already done from previous run)")

    updated = 0
    for i, actor in enumerate(remaining):
        aid = actor.get("id", "")
        if not aid:
            continue

        queries = [actor.get("name", "")] + (actor.get("aliases") or [])[:2]
        queries = list(dict.fromkeys(q for q in queries if q))[:2]

        all_pulses, seen_ids = [], set()
        log.info(f"[{done_count+i+1}/{len(priority)}] {aid}")

        for q in queries:
            data = _get(session, f"{OTX_BASE}/search/pulses",
                        {"q": q, "sort": "-modified", "limit": pulse_limit, "page": 1},
                        sleep)
            if not data:
                continue
            for p in data.get("results", []):
                pid = p.get("id", "")
                if pid and pid not in seen_ids:
                    seen_ids.add(pid)
                    all_pulses.append(_pulse_meta(p))

        entry = ioc_data["actors"].setdefault(aid, {
            "pulses": [], "indicators": _empty_ind(), "updated": "",
        })
        now = datetime.now(timezone.utc).isoformat()
        if all_pulses:
            entry["pulses"] = all_pulses[:50]
            entry["updated"] = now
            updated += 1
            log.info(f"  → {len(all_pulses)} pulses")
        else:
            log.info(f"  → no results")

        # Mark as searched regardless of results — enables checkpoint/resume
        entry["full_searched_at"] = now

        if (i + 1) % 10 == 0:
            _write(DATA_DIR / "ioc.json", ioc_data)
            log.info(f"Checkpoint saved: {done_count+i+1}/{len(priority)} actors processed "
                     f"({updated} with pulses this run)")

    # Final save
    _write(DATA_DIR / "ioc.json", ioc_data)
    total_done = done_count + len(remaining)
    log.info(f"Full fetch run complete: {updated} actors with new pulses this run, "
             f"{total_done}/{len(priority)} actors total searched")


# ── Mode: incremental daily ────────────────────────────────────────────────────

def run_incremental(session: requests.Session, sleep: float, hours: int,
                    actor_index: dict, ioc_data: dict) -> None:
    """
    Fetch pulses modified in last N hours.
    For each pulse: get full indicators, map to matching actors, update feed.
    """
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    log.info(f"Incremental fetch: pulses since {since} ({hours}h window)")

    feed_ind = _empty_ind()
    total_pulses = 0
    actor_updates: dict[str, int] = {}

    page = 1
    while page <= 20:  # max 2000 recent pulses
        data = _get(session, f"{OTX_BASE}/pulses/subscribed",
                    {"modified_since": since, "limit": 100, "page": page}, sleep)
        if not data:
            break
        results = data.get("results", [])
        if not results:
            break

        for pulse in results:
            total_pulses += 1
            meta  = _pulse_meta(pulse)
            pid   = meta["id"]

            # Full indicator fetch for this pulse
            raw_inds = _fetch_pulse_indicators(session, pid, sleep)

            # Global feed
            _merge_ind(feed_ind, raw_inds)

            # Map to actors
            matched = _match_pulse_actors(pulse, actor_index)
            for aid in matched:
                entry = ioc_data["actors"].setdefault(aid, {
                    "pulses": [], "indicators": _empty_ind(), "updated": "",
                })
                existing = {p["id"] for p in entry["pulses"]}
                if pid not in existing:
                    entry["pulses"].insert(0, meta)
                    entry["pulses"] = entry["pulses"][:50]
                _merge_ind(entry["indicators"], raw_inds)
                entry["updated"] = datetime.now(timezone.utc).isoformat()
                actor_updates[aid] = actor_updates.get(aid, 0) + 1

        if not data.get("next"):
            break
        page += 1

    # Store global IOC feed (last 24h, max 1000 per type)
    ioc_data["feed"] = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "since":   since,
        **{k: v[:1000] for k, v in feed_ind.items() if v},
    }

    log.info(
        f"Incremental done: {total_pulses} pulses, "
        f"{len(actor_updates)} actors updated"
    )


# ── Mode: group feeds ──────────────────────────────────────────────────────────

def run_groups(session: requests.Session, sleep: float, ioc_data: dict) -> None:
    """Fetch pulses from curated OTX groups."""
    log.info(f"Fetching {len(KNOWN_GROUPS)} OTX groups")

    for gid, gname in KNOWN_GROUPS:
        log.info(f"  Group {gid}: {gname}")
        # Try both endpoint variants
        data = (
            _get(session, f"{OTX_BASE}/groups/{gid}/pulses",
                 {"limit": 40, "sort": "-modified"}, sleep) or
            _get(session, f"{OTX_BASE}/group/{gid}/pulses",
                 {"limit": 40, "sort": "-modified"}, sleep)
        )
        if not data:
            log.warning(f"  Group {gid} not accessible — skipping")
            continue

        pulses = [_pulse_meta(p) for p in data.get("results", [])]
        if not pulses:
            continue

        ioc_data["groups"][str(gid)] = {
            "name":    gname,
            "pulses":  pulses,
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        log.info(f"  → {len(pulses)} pulses")


# ── Entry point ────────────────────────────────────────────────────────────────

def run(api_key: str = "", mode_full: bool = False, mode_groups: bool = False,
        hours: int = 26, pulse_limit: int = 20) -> None:

    api_key = api_key or os.environ.get("OTX_API_KEY", "")
    sleep   = SLEEP_AUTH if api_key else SLEEP_NOAUTH

    if api_key:
        log.info("OTX API key detected — authenticated mode (high rate limit)")
    else:
        log.warning("No OTX_API_KEY — public mode (6.5s/req, very slow)")

    actors_path = DATA_DIR / "actors.json"
    if not actors_path.exists():
        log.error("actors.json not found — run fetch_all.py first")
        return

    actors   = json.loads(actors_path.read_text(encoding="utf-8"))
    ioc_path = DATA_DIR / "ioc.json"
    ioc_data = _load_ioc(ioc_path)
    session  = _session(api_key)

    if mode_full:
        run_full(session, sleep, actors, ioc_data, pulse_limit)

    if mode_groups:
        run_groups(session, sleep, ioc_data)

    if not mode_full and not mode_groups:
        actor_index = _build_actor_index(actors)
        run_incremental(session, sleep, hours, actor_index, ioc_data)

    # Update meta
    now = datetime.now(timezone.utc).isoformat()
    meta = ioc_data.get("meta", {})
    ioc_data["meta"] = {
        "last_full":        now if mode_full else meta.get("last_full", ""),
        "last_incremental": now if not mode_full else meta.get("last_incremental", ""),
        "actor_coverage":   sum(1 for v in ioc_data["actors"].values() if v.get("pulses")),
        "group_count":      len(ioc_data["groups"]),
        "feed_updated":     ioc_data.get("feed", {}).get("updated", ""),
    }

    _write(ioc_path, ioc_data)
    log.info(
        f"ioc.json saved — actors: {ioc_data['meta']['actor_coverage']}, "
        f"groups: {ioc_data['meta']['group_count']}"
    )


if __name__ == "__main__":
    args  = sys.argv[1:]
    hours = 26
    limit = 20
    for i, a in enumerate(args):
        if a == "--hours" and i + 1 < len(args):
            hours = int(args[i + 1])
        elif a == "--limit" and i + 1 < len(args):
            limit = int(args[i + 1])

    run(
        mode_full   = "--full"   in args,
        mode_groups = "--groups" in args,
        hours       = hours,
        pulse_limit = limit,
    )
