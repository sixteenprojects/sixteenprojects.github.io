#!/usr/bin/env python3
"""
CISA KEV Data Pipeline — The Sixteen Project
Fetches CISA KEV catalog + bulk CVSS data via NVD hasKev endpoint.

Usage:
  python scripts/fetch_kev.py               # Fetch CISA + NVD CVSS (default, ~10s)
  python scripts/fetch_kev.py --no-nvd      # CISA only, skip CVSS
  python scripts/fetch_kev.py --api-key KEY # With NVD API key (higher rate limit)
  python scripts/fetch_kev.py --force       # Re-fetch NVD even if cache is fresh
"""

import json
import time
import os
import sys
import argparse
from datetime import datetime, timezone, timedelta

try:
    import requests
except ImportError:
    print("Missing 'requests'. Run: pip install requests")
    sys.exit(1)

CISA_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_HASKEV_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev"
NVD_PAGE_SIZE   = 2000
CACHE_TTL_HOURS = 12


# ─────────────────────────────────────────────
#  CISA
# ─────────────────────────────────────────────

def fetch_cisa_kev():
    print("[*] Fetching CISA KEV catalog...")
    resp = requests.get(CISA_KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    print(f"    {data['count']} vulnerabilities  (catalog v{data.get('catalogVersion', '?')})")
    return data


# ─────────────────────────────────────────────
#  NVD BULK (hasKev)
# ─────────────────────────────────────────────

def load_nvd_cache(cache_file):
    """Load NVD cache if it exists and is fresh enough."""
    if not os.path.exists(cache_file):
        return None
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            cached = json.load(f)
        ts  = datetime.fromisoformat(cached['timestamp'].replace('Z', '+00:00'))
        age = datetime.now(timezone.utc) - ts
        if age < timedelta(hours=CACHE_TTL_HOURS):
            hrs = round(age.total_seconds() / 3600, 1)
            print(f"[*] NVD cache hit ({hrs}h old, TTL {CACHE_TTL_HOURS}h) — skipping API call")
            return cached['data']
        print(f"[*] NVD cache expired ({round(age.total_seconds()/3600,1)}h old) — re-fetching")
    except (KeyError, ValueError, json.JSONDecodeError):
        print("[*] NVD cache corrupt — re-fetching")
    return None


def save_nvd_cache(cache_file, nvd_map):
    os.makedirs(os.path.dirname(os.path.abspath(cache_file)), exist_ok=True)
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump({
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'data': nvd_map
        }, f, separators=(',', ':'))
    print(f"[*] NVD cache saved ({len(nvd_map)} entries) -> {cache_file}")


def extract_cvss(metrics):
    """Return best available CVSS from a metrics block (v3.1 > v3.0 > v2.0)."""
    for version_key, cvss_version in [
        ('cvssMetricV31', '3.1'),
        ('cvssMetricV30', '3.0'),
        ('cvssMetricV2',  '2.0'),
    ]:
        for m in metrics.get(version_key, []):
            if m.get('type') == 'Primary':
                cd = m.get('cvssData', {})
                severity = cd.get('baseSeverity') or m.get('baseSeverity')
                return {
                    'cvssScore':   cd.get('baseScore'),
                    'cvssVector':  cd.get('vectorString'),
                    'cvssVersion': cvss_version,
                    'severity':    severity.upper() if severity else None,
                }
    return None


def fetch_nvd_haskev(api_key=None):
    """
    Bulk-fetch all NVD entries flagged as KEV via the ?hasKev filter.
    Returns a dict keyed by CVE ID.

    Why this is fast: one API call returns all ~1600 KEV CVEs at once
    (vs. the old approach: 1600 individual calls × 6.2s delay = ~3 hours).
    """
    headers = {'User-Agent': 'sixteen-project-kev/2.0'}
    if api_key:
        headers['apiKey'] = api_key

    # NVD rate limits: 5 req/30s (no key) | 50 req/30s (with key)
    # With 2000 results/page and ~1600 KEVs, usually 1 page = 1 request.
    page_delay = 0.65 if api_key else 6.5

    session     = requests.Session()
    nvd_map     = {}
    start_index = 0
    page_num    = 0

    print("[*] Fetching NVD hasKev bulk data (https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev)...")

    while True:
        url = f"{NVD_HASKEV_URL}&startIndex={start_index}&resultsPerPage={NVD_PAGE_SIZE}"
        try:
            resp = session.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as e:
            print(f"    [!] NVD request failed: {e}", file=sys.stderr)
            break

        total    = data.get('totalResults', 0)
        per_page = data.get('resultsPerPage', NVD_PAGE_SIZE)
        vulns    = data.get('vulnerabilities', [])
        page_num += 1
        print(f"    Page {page_num}: {len(vulns)} CVEs  (total: {total})")

        for item in vulns:
            cve_obj = item.get('cve', {})
            cve_id  = cve_obj.get('id')
            if not cve_id:
                continue
            cvss = extract_cvss(cve_obj.get('metrics', {}))
            nvd_map[cve_id] = cvss or {
                'cvssScore': None, 'cvssVector': None,
                'cvssVersion': None, 'severity': None,
            }

        start_index += per_page
        if start_index >= total:
            break

        print(f"    Next page in {page_delay}s...")
        time.sleep(page_delay)

    scored = sum(1 for v in nvd_map.values() if v.get('cvssScore') is not None)
    print(f"    Done: {len(nvd_map)} CVEs fetched, {scored} with CVSS score")
    return nvd_map


# ─────────────────────────────────────────────
#  OUTPUT BUILDER
# ─────────────────────────────────────────────

def build_output(kev_data, vuln_list, nvd_map, enriched):
    output_vulns = []
    for v in vuln_list:
        entry = dict(v)

        date_str = v.get('dateAdded', '')
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%d')
            entry['year']  = dt.year
            entry['month'] = dt.month
        except (ValueError, TypeError):
            entry['year']  = None
            entry['month'] = None

        nvd = nvd_map.get(v['cveID']) or {}
        entry['cvssScore']   = nvd.get('cvssScore')
        entry['cvssVector']  = nvd.get('cvssVector')
        entry['cvssVersion'] = nvd.get('cvssVersion')
        entry['severity']    = nvd.get('severity')

        output_vulns.append(entry)

    enriched_count = sum(1 for v in output_vulns if v.get('cvssScore') is not None)

    return {
        'metadata': {
            'source':         'CISA Known Exploited Vulnerabilities Catalog',
            'catalogVersion': kev_data.get('catalogVersion', ''),
            'dateReleased':   kev_data.get('dateReleased', ''),
            'lastFetched':    datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'totalCount':     len(output_vulns),
            'enriched':       enriched,
            'enrichedCount':  enriched_count,
        },
        'vulnerabilities': output_vulns,
    }


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Fetch CISA KEV + NVD CVSS data')
    parser.add_argument('--no-nvd',  action='store_true',            help='Skip NVD CVSS enrichment')
    parser.add_argument('--api-key', metavar='KEY',                   help='NVD API key (50 req/30s vs 5 req/30s)')
    parser.add_argument('--force',   action='store_true',            help='Force NVD re-fetch even if cache is fresh')
    parser.add_argument('--output',  default='data/kev_data.json',   help='Output JSON path')
    parser.add_argument('--cache',   default='data/nvd_haskev_cache.json', help='NVD bulk cache path')
    args = parser.parse_args()

    kev_data  = fetch_cisa_kev()
    vuln_list = kev_data.get('vulnerabilities', [])

    nvd_map  = {}
    enriched = False

    if not args.no_nvd:
        # Try cache first (unless --force)
        if not args.force:
            nvd_map = load_nvd_cache(args.cache) or {}

        if not nvd_map:
            nvd_map = fetch_nvd_haskev(args.api_key)
            save_nvd_cache(args.cache, nvd_map)

        enriched = True

    output = build_output(kev_data, vuln_list, nvd_map, enriched)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, separators=(',', ':'))

    print(f"\n[+] Done -> {args.output}")
    print(f"    Total CVEs : {output['metadata']['totalCount']}")
    print(f"    With CVSS  : {output['metadata']['enrichedCount']}")
    if not enriched:
        print(f"\n    Tip: run without --no-nvd to include CVSS severity data")


if __name__ == '__main__':
    main()
