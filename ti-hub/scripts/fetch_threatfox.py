"""
fetch_threatfox.py — abuse.ch ecosystem intelligence fetch

Sources (all free, no API key required):
  ThreatFox     https://threatfox.abuse.ch/       IOCs per malware family
  MalwareBazaar https://bazaar.abuse.ch/           File samples per malware
  URLhaus       https://urlhaus.abuse.ch/          Malicious URLs
  FeodoTracker  https://feodotracker.abuse.ch/     Botnet C2 servers

Uses export/download URLs (CDN-hosted) instead of API endpoints to avoid
IP-based blocking on cloud CI runners (Azure, GitHub Actions, etc.).

Output: data/threatfox.json
  {
    "malware":  { malware_id: { iocs, samples, urls, updated } },
    "urlhaus":  { urls: [...], updated },
    "feodo":    { c2s: [...], updated },
    "recent":   { iocs: [...], updated },
    "meta":     { ... }
  }

Usage:
  python fetch_threatfox.py              # full fetch
  python fetch_threatfox.py --days 1    # only last N days for incremental
"""

import csv
import io
import json
import logging
import sys
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    sys.exit("Install requests: pip install requests")

DATA_DIR = Path(__file__).parent.parent / "data"
SLEEP    = 1.0   # seconds between requests (be polite)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ThreatFox] %(message)s")
log = logging.getLogger("ThreatFox")

# Export / download URLs — CDN-hosted, not blocked by IP filtering
THREATFOX_EXPORT = "https://threatfox.abuse.ch/export/json/recent/"
BAZAAR_EXPORT    = "https://bazaar.abuse.ch/export/csv/recent/"
URLHAUS_EXPORT   = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_JSON       = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get_bytes(url: str) -> bytes | None:
    try:
        r = requests.get(url, timeout=60,
                         headers={"User-Agent": "TheSixteenProject-TIHub/2.0"})
        r.raise_for_status()
        time.sleep(SLEEP)
        return r.content
    except Exception as e:
        log.warning(f"GET {url}: {e}")
        return None


def _get(url: str) -> dict | list | None:
    try:
        r = requests.get(url, timeout=30,
                         headers={"User-Agent": "TheSixteenProject-TIHub/2.0"})
        r.raise_for_status()
        time.sleep(SLEEP)
        return r.json()
    except Exception as e:
        log.warning(f"GET {url}: {e}")
        return None


def _unzip_first(data: bytes) -> bytes | None:
    """Extract the first file from a ZIP archive."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            if not names:
                return None
            log.info(f"  ZIP contains: {names}")
            return zf.read(names[0])
    except Exception as e:
        log.warning(f"ZIP extract error: {e}")
        return None


# ── ThreatFox ─────────────────────────────────────────────────────────────────

def _tf_ioc_entry(ioc: dict) -> dict:
    return {
        "id":            ioc.get("id", ""),
        "value":         ioc.get("ioc", ""),
        "type":          ioc.get("ioc_type", ""),
        "malware":       ioc.get("malware", ""),
        "malware_alias": ioc.get("malware_alias", ""),
        "confidence":    ioc.get("confidence_level", 0),
        "threat_type":   ioc.get("threat_type", ""),
        "first_seen":    (ioc.get("first_seen") or "")[:10],
        "last_seen":     (ioc.get("last_seen") or "")[:10],
        "tags":          ioc.get("tags") or [],
        "reporter":      ioc.get("reporter", ""),
        "reference":     ioc.get("reference", ""),
    }


def fetch_threatfox_recent(days: int = 3) -> list:
    """Fetch recent IOCs from ThreatFox via export ZIP (CDN, not IP-blocked)."""
    log.info("ThreatFox: recent IOCs (export download)")
    raw = _get_bytes(THREATFOX_EXPORT)
    if not raw:
        return []

    content = _unzip_first(raw) if raw[:2] == b"PK" else raw
    if not content:
        log.warning("ThreatFox: could not extract content")
        return []

    try:
        export_data = json.loads(content)
    except Exception as e:
        log.warning(f"ThreatFox JSON parse error: {e}")
        return []

    iocs = []
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

    if isinstance(export_data, list):
        # Plain array of IOC objects
        iocs = [_tf_ioc_entry(item) for item in export_data]
    elif isinstance(export_data, dict):
        if "data" in export_data:
            # {"data": [...]} format
            iocs = [_tf_ioc_entry(item) for item in (export_data["data"] or [])]
        else:
            # Date-keyed format: {"YYYY-MM-DD": [...], ...}
            for date_key, items in export_data.items():
                if not isinstance(items, list) or date_key < cutoff:
                    continue
                iocs.extend(_tf_ioc_entry(item) for item in items)

    log.info(f"  → {len(iocs)} IOCs (last {days} days)")
    return iocs


# ── MalwareBazaar ─────────────────────────────────────────────────────────────

def _bz_csv_entry(row: dict) -> dict:
    tags_raw = row.get("tags") or ""
    tags = [t.strip() for t in tags_raw.replace("|", ",").split(",") if t.strip()]
    return {
        "sha256":     row.get("sha256_hash", ""),
        "sha1":       row.get("sha1_hash", ""),
        "md5":        row.get("md5_hash", ""),
        "file_name":  row.get("file_name", ""),
        "file_type":  row.get("file_type_guess", ""),
        "file_size":  0,
        "malware":    row.get("signature", ""),
        "tags":       tags,
        "first_seen": (row.get("first_seen_utc") or "")[:10],
        "imphash":    row.get("imphash", ""),
        "reporter":   row.get("reporter", ""),
        "origin":     "",
    }


def fetch_bazaar_recent(limit: int = 200) -> list:
    """Fetch recent malware samples from MalwareBazaar via export CSV ZIP."""
    log.info("MalwareBazaar: recent samples (export download)")
    raw = _get_bytes(BAZAAR_EXPORT)
    if not raw:
        return []

    content = _unzip_first(raw) if raw[:2] == b"PK" else raw
    if not content:
        log.warning("MalwareBazaar: could not extract content")
        return []

    try:
        text = content.decode("utf-8", errors="replace")
        lines = [l for l in text.splitlines() if not l.startswith("#") and l.strip()]
        reader = csv.DictReader(lines)
        samples = [_bz_csv_entry(row) for row in reader
                   if row.get("sha256_hash")][:limit]
    except Exception as e:
        log.warning(f"MalwareBazaar CSV parse error: {e}")
        return []

    log.info(f"  → {len(samples)} samples")
    return samples


# ── URLhaus ───────────────────────────────────────────────────────────────────

def _uh_csv_entry(row: dict) -> dict:
    url = row.get("url", "")
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    tags_raw = row.get("tags") or ""
    tags = [t.strip() for t in tags_raw.replace("|", ",").split(",") if t.strip()]
    return {
        "id":         row.get("id", ""),
        "url":        url,
        "url_status": row.get("url_status", ""),
        "host":       host,
        "date_added": (row.get("dateadded") or "")[:10],
        "threat":     row.get("threat", ""),
        "tags":       tags,
        "malware":    "",
        "reporter":   row.get("reporter", ""),
    }


def fetch_urlhaus_recent(limit: int = 500) -> list:
    """Fetch recent malicious URLs from URLhaus via export CSV ZIP."""
    log.info("URLhaus: recent URLs (export download)")
    raw = _get_bytes(URLHAUS_EXPORT)
    if not raw:
        return []

    content = _unzip_first(raw) if raw[:2] == b"PK" else raw
    if not content:
        log.warning("URLhaus: could not extract content")
        return []

    try:
        text = content.decode("utf-8", errors="replace")
        lines = [l for l in text.splitlines() if not l.startswith("#") and l.strip()]
        reader = csv.DictReader(lines)
        urls = [_uh_csv_entry(row) for row in reader
                if row.get("url")][:limit]
    except Exception as e:
        log.warning(f"URLhaus CSV parse error: {e}")
        return []

    log.info(f"  → {len(urls)} URLs")
    return urls


# ── FeodoTracker ──────────────────────────────────────────────────────────────

def _feodo_entry(c: dict) -> dict:
    return {
        "ip":          c.get("ip_address", ""),
        "port":        c.get("port", 0),
        "status":      c.get("status", ""),
        "malware":     c.get("malware", ""),
        "first_seen":  (c.get("first_seen") or "")[:10],
        "last_online": (c.get("last_online") or "")[:10],
        "country":     c.get("country", ""),
        "asn":         c.get("as_number", ""),
        "as_name":     c.get("as_name", ""),
    }


def fetch_feodo() -> list:
    """Fetch botnet C2 blocklist from FeodoTracker (direct download, not blocked)."""
    log.info("FeodoTracker: C2 blocklist")
    data = _get(FEODO_JSON)
    if not isinstance(data, list):
        log.warning("FeodoTracker: unexpected response format")
        return []
    entries = [_feodo_entry(c) for c in data]
    log.info(f"  → {len(entries)} C2 servers")
    return entries


# ── Build per-malware index ───────────────────────────────────────────────────

def _normalise_malware_name(name: str) -> str:
    """Lowercase, strip Win./ Linux./ etc prefixes for matching."""
    n = (name or "").lower().strip()
    for prefix in ["win.", "linux.", "android.", "osx.", "macos.", "multi.", "js.", "doc."]:
        if n.startswith(prefix):
            n = n[len(prefix):]
    return n


def _build_malware_index(malware_list: list) -> dict:
    """Map normalised names/aliases to Malpedia malware IDs."""
    index = {}
    for m in malware_list:
        mid = m.get("id", "")
        if not mid:
            continue
        names = [m.get("name", "")] + (m.get("aliases") or [])
        for n in names:
            if n:
                index[_normalise_malware_name(n)] = mid
    return index


def _map_iocs_to_malware(iocs: list, malware_index: dict) -> dict[str, list]:
    """Group ThreatFox IOCs by Malpedia malware ID."""
    grouped: dict[str, list] = {}
    for ioc in iocs:
        raw = ioc.get("malware", "") or ioc.get("malware_alias", "")
        key = _normalise_malware_name(raw)
        mid = malware_index.get(key)
        if not mid:
            for name, m in malware_index.items():
                if len(name) >= 4 and (name in key or key in name):
                    mid = m
                    break
        if mid:
            grouped.setdefault(mid, []).append(ioc)
    return grouped


def _map_samples_to_malware(samples: list, malware_index: dict) -> dict[str, list]:
    grouped: dict[str, list] = {}
    for s in samples:
        key = _normalise_malware_name(s.get("malware", ""))
        mid = malware_index.get(key)
        if mid:
            grouped.setdefault(mid, []).append(s)
    return grouped


# ── IO ─────────────────────────────────────────────────────────────────────────

def _load(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"malware": {}, "urlhaus": {}, "feodo": {}, "recent": {}, "meta": {}}


def _write(path: Path, data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )


# ── Entry point ────────────────────────────────────────────────────────────────

def run(days: int = 3) -> None:
    now = datetime.now(timezone.utc).isoformat()

    malware_path = DATA_DIR / "malware.json"
    malware_list = []
    if malware_path.exists():
        malware_list = json.loads(malware_path.read_text(encoding="utf-8"))
    malware_index = _build_malware_index(malware_list)
    log.info(f"Malware index: {len(malware_index)} names from Malpedia")

    tf_path = DATA_DIR / "threatfox.json"
    data    = _load(tf_path)

    # ── ThreatFox recent IOCs ──────────────────────────────────────────────────
    recent_iocs = fetch_threatfox_recent(days=days)
    ioc_by_malware = _map_iocs_to_malware(recent_iocs, malware_index)

    for mid, iocs in ioc_by_malware.items():
        entry = data["malware"].setdefault(mid, {"iocs": [], "samples": [], "updated": ""})
        existing_ids = {i["id"] for i in entry["iocs"]}
        for ioc in iocs:
            if ioc["id"] not in existing_ids:
                entry["iocs"].insert(0, ioc)
        entry["iocs"] = entry["iocs"][:200]
        entry["updated"] = now

    data["recent"]["iocs"]    = recent_iocs[:500]
    data["recent"]["updated"] = now

    # ── MalwareBazaar recent samples ──────────────────────────────────────────
    recent_samples = fetch_bazaar_recent()
    sample_by_malware = _map_samples_to_malware(recent_samples, malware_index)

    for mid, samples in sample_by_malware.items():
        entry = data["malware"].setdefault(mid, {"iocs": [], "samples": [], "updated": ""})
        existing_hashes = {s["sha256"] for s in entry["samples"]}
        for s in samples:
            if s["sha256"] not in existing_hashes:
                entry["samples"].insert(0, s)
        entry["samples"] = entry["samples"][:100]
        entry["updated"] = now

    # ── URLhaus recent URLs ────────────────────────────────────────────────────
    urls = fetch_urlhaus_recent()
    data["urlhaus"] = {"urls": urls, "updated": now}

    # ── FeodoTracker C2 blocklist ──────────────────────────────────────────────
    c2s = fetch_feodo()
    data["feodo"] = {"c2s": c2s, "updated": now}

    # ── Meta ──────────────────────────────────────────────────────────────────
    data["meta"] = {
        "updated":         now,
        "malware_covered": len(data["malware"]),
        "total_iocs":      sum(len(v.get("iocs", [])) for v in data["malware"].values()),
        "total_samples":   sum(len(v.get("samples", [])) for v in data["malware"].values()),
        "urlhaus_count":   len(urls),
        "feodo_count":     len(c2s),
    }

    _write(tf_path, data)
    log.info(
        f"Done. Malware covered: {data['meta']['malware_covered']}, "
        f"IOCs: {data['meta']['total_iocs']}, "
        f"Samples: {data['meta']['total_samples']}, "
        f"C2s: {data['meta']['feodo_count']}"
    )


if __name__ == "__main__":
    args = sys.argv[1:]
    days = 3
    for i, a in enumerate(args):
        if a == "--days" and i + 1 < len(args):
            days = int(args[i + 1])
    run(days=days)
