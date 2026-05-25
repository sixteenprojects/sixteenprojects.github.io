"""
fetch_shodan.py — Shodan IP enrichment & CVE exposure

Uses SHODAN_API_KEY env variable (paid plan recommended).

What it fetches:
  1. Host enrichment  — for C2 IPs from ThreatFox/FeodoTracker:
                        country, org, ASN, open ports, banners, CVEs detected
  2. CVE exposure     — for each CISA KEV CVE: count of internet-facing
                        vulnerable systems (uses /host/count, costs NO credits)

Output: data/shodan.json
  {
    "hosts":        { ip: { country, city, org, asn, ports, cves, hostnames, updated } },
    "cve_exposure": { "CVE-XXXX-XXXX": count },
    "meta":         { hosts_total, cves_enriched, updated, credits_remaining }
  }

Credit usage:
  - /host/{ip}          : 1 query credit per IP
  - /host/count?query=  : 0 credits (free)
  Hosts are cached in shodan.json — only NEW IPs are queried each run.

Usage:
  python fetch_shodan.py               # enrich new IPs + CVE exposure
  python fetch_shodan.py --cve-only    # only CVE exposure (free, no credits)
  python fetch_shodan.py --max-ips 500 # limit new IP lookups per run
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
    sys.exit("Install requests: pip install requests")

DATA_DIR    = Path(__file__).parent.parent / "data"
SHODAN_BASE = "https://api.shodan.io"
SLEEP       = 1.1   # stay under 1 req/sec for free tier; paid can go faster

logging.basicConfig(level=logging.INFO, format="%(asctime)s [Shodan] %(message)s")
log = logging.getLogger("Shodan")


# ── Session ───────────────────────────────────────────────────────────────────

def _session(api_key: str) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "TheSixteenProject-TIHub/2.0"
    s.params = {"key": api_key}  # type: ignore
    return s


def _get(session: requests.Session, path: str, params: dict = {}) -> dict | None:
    try:
        r = session.get(f"{SHODAN_BASE}{path}", params=params, timeout=15)
        if r.status_code == 401:
            log.error("Shodan 401 — check SHODAN_API_KEY")
            return None
        if r.status_code == 429:
            log.warning("Rate limited — sleeping 30s")
            time.sleep(30)
            r = session.get(f"{SHODAN_BASE}{path}", params=params, timeout=15)
        if r.status_code == 404:
            return {}   # IP not in Shodan
        r.raise_for_status()
        time.sleep(SLEEP)
        return r.json()
    except Exception as e:
        log.warning(f"Shodan {path}: {e}")
        return None


# ── Host lookup ───────────────────────────────────────────────────────────────

def _host_entry(data: dict, ip: str) -> dict:
    return {
        "ip":        ip,
        "country":   data.get("country_code", ""),
        "city":      data.get("city", ""),
        "org":       data.get("org", ""),
        "isp":       data.get("isp", ""),
        "asn":       data.get("asn", ""),
        "hostnames": (data.get("hostnames") or [])[:5],
        "ports":     sorted(data.get("ports") or [])[:20],
        "tags":      data.get("tags") or [],
        "cves":      list({
            cve
            for item in (data.get("data") or [])
            for cve in (item.get("vulns") or {}).keys()
        })[:20],
        "os":        data.get("os", ""),
        "updated":   datetime.now(timezone.utc).isoformat()[:10],
    }


def enrich_hosts(session: requests.Session, ips: list[str],
                 existing: dict, max_ips: int) -> dict:
    """Lookup new IPs in Shodan (skips already-cached IPs)."""
    new_ips = [ip for ip in ips if ip not in existing][:max_ips]
    log.info(f"Host enrichment: {len(new_ips)} new IPs (of {len(ips)} total, {len(ips)-len(new_ips)} cached)")

    enriched = 0
    for i, ip in enumerate(new_ips):
        data = _get(session, f"/shodan/host/{ip}")
        if data is None:
            break   # auth error — stop
        if data:
            existing[ip] = _host_entry(data, ip)
            enriched += 1
        if (i + 1) % 50 == 0:
            log.info(f"  Progress: {i+1}/{len(new_ips)} IPs")

    log.info(f"  → {enriched} hosts enriched")
    return existing


# ── CVE exposure ──────────────────────────────────────────────────────────────

def fetch_cve_exposure(session: requests.Session, cve_ids: list[str],
                       existing: dict) -> dict:
    """
    Count internet-facing systems vulnerable to each CVE.
    Uses /host/count which does NOT consume Shodan credits.
    Only queries CVEs not already cached.
    """
    new_cves = [c for c in cve_ids if c not in existing]
    log.info(f"CVE exposure: {len(new_cves)} new CVEs (of {len(cve_ids)}, {len(cve_ids)-len(new_cves)} cached)")

    for i, cve_id in enumerate(new_cves):
        data = _get(session, "/shodan/host/count", {"query": f"vuln:{cve_id}"})
        if data is None:
            break   # auth error
        count = data.get("total", 0) if data else 0
        existing[cve_id] = count

        if (i + 1) % 100 == 0:
            log.info(f"  Progress: {i+1}/{len(new_cves)} CVEs")

    log.info(f"  → {len(new_cves)} CVEs queried")
    return existing


# ── Collect IPs from data sources ─────────────────────────────────────────────

def _collect_ips(data_dir: Path) -> list[str]:
    """Gather unique malicious IPs from ThreatFox and FeodoTracker."""
    ips = set()

    # FeodoTracker C2 IPs
    tf_path = data_dir / "threatfox.json"
    if tf_path.exists():
        try:
            tf = json.loads(tf_path.read_text(encoding="utf-8"))
            for c2 in (tf.get("feodo", {}).get("c2s") or []):
                ip = c2.get("ip", "")
                if ip:
                    ips.add(ip)
            # Also collect IPs from ThreatFox recent IOCs
            for ioc in (tf.get("recent", {}).get("iocs") or []):
                if ioc.get("type") in ("ip:port", "ip") and ioc.get("value"):
                    raw = ioc["value"].split(":")[0]
                    if raw:
                        ips.add(raw)
        except Exception as e:
            log.warning(f"Could not load threatfox.json: {e}")

    # OTX actor IOC IPs
    ioc_path = data_dir / "ioc.json"
    if ioc_path.exists():
        try:
            ioc = json.loads(ioc_path.read_text(encoding="utf-8"))
            actors = ioc.get("actors", ioc)  # handle old flat format
            for actor_data in actors.values():
                if not isinstance(actor_data, dict):
                    continue
                for ip in (actor_data.get("indicators", {}).get("ip") or []):
                    ips.add(ip)
        except Exception as e:
            log.warning(f"Could not load ioc.json: {e}")

    log.info(f"Collected {len(ips)} unique IPs from threat data sources")
    return list(ips)


def _collect_cves(data_dir: Path) -> list[str]:
    """Gather CVE IDs from CISA KEV data."""
    cves = []

    # Try actors.json (has KEV-linked CVEs)
    actors_path = data_dir / "actors.json"
    if actors_path.exists():
        try:
            actors = json.loads(actors_path.read_text(encoding="utf-8"))
            for a in actors:
                for cve in (a.get("cves") or []):
                    if cve.startswith("CVE-") and cve not in cves:
                        cves.append(cve)
        except Exception:
            pass

    # Try stats.json for top CVEs
    stats_path = data_dir / "stats.json"
    if stats_path.exists():
        try:
            stats = json.loads(stats_path.read_text(encoding="utf-8"))
            for item in (stats.get("top_cves") or []):
                cve = item.get("cve", "")
                if cve and cve not in cves:
                    cves.append(cve)
        except Exception:
            pass

    # Read from KEV data directory if it exists
    kev_path = data_dir.parent.parent / "data" / "kev.json"
    if kev_path.exists():
        try:
            kev = json.loads(kev_path.read_text(encoding="utf-8"))
            vulns = kev if isinstance(kev, list) else kev.get("vulnerabilities", [])
            for v in vulns:
                cve = v.get("cveID", "") or v.get("id", "")
                if cve and cve not in cves:
                    cves.append(cve)
        except Exception:
            pass

    log.info(f"Collected {len(cves)} CVEs for exposure check")
    return cves[:2000]   # limit to avoid excessive API calls


# ── IO ─────────────────────────────────────────────────────────────────────────

def _load(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"hosts": {}, "cve_exposure": {}, "meta": {}}


def _write(path: Path, data: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )


# ── API info ──────────────────────────────────────────────────────────────────

def _get_api_info(session: requests.Session) -> dict:
    data = _get(session, "/api-info")
    return data or {}


# ── Entry point ────────────────────────────────────────────────────────────────

def run(api_key: str = "", cve_only: bool = False, max_ips: int = 300) -> None:
    api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        log.error("SHODAN_API_KEY not set — skipping Shodan enrichment")
        return

    session  = _session(api_key)
    out_path = DATA_DIR / "shodan.json"
    data     = _load(out_path)
    now      = datetime.now(timezone.utc).isoformat()

    # Check API info / credits
    info = _get_api_info(session)
    if not info:
        log.error("Could not connect to Shodan API — check key")
        return
    credits = info.get("query_credits", "?")
    scan_credits = info.get("scan_credits", "?")
    plan = info.get("plan", "?")
    log.info(f"Shodan plan: {plan} | query credits: {credits} | scan credits: {scan_credits}")

    # ── CVE exposure (free — no credits consumed) ──────────────────────────────
    cve_ids = _collect_cves(DATA_DIR)
    if cve_ids:
        data["cve_exposure"] = fetch_cve_exposure(session, cve_ids, data.get("cve_exposure", {}))
        _write(out_path, data)

    if cve_only:
        log.info("--cve-only mode: skipping host enrichment")
    else:
        # ── Host enrichment (costs 1 credit per new IP) ────────────────────────
        ips = _collect_ips(DATA_DIR)
        if ips:
            data["hosts"] = enrich_hosts(session, ips, data.get("hosts", {}), max_ips)
            _write(out_path, data)

    # ── Meta ──────────────────────────────────────────────────────────────────
    data["meta"] = {
        "updated":          now,
        "plan":             plan,
        "credits_remaining":credits,
        "hosts_total":      len(data.get("hosts", {})),
        "cves_enriched":    len(data.get("cve_exposure", {})),
    }
    _write(out_path, data)
    log.info(
        f"Done. Hosts: {data['meta']['hosts_total']}, "
        f"CVEs: {data['meta']['cves_enriched']}, "
        f"Credits remaining: {credits}"
    )


if __name__ == "__main__":
    args     = sys.argv[1:]
    max_ips  = 300
    for i, a in enumerate(args):
        if a == "--max-ips" and i + 1 < len(args):
            max_ips = int(args[i + 1])

    run(
        cve_only = "--cve-only" in args,
        max_ips  = max_ips,
    )
