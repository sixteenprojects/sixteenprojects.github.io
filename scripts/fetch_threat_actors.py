#!/usr/bin/env python3
"""
Build CVE -> Threat Actor attribution map from MITRE ATT&CK STIX data.
Source: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

Approach:
  1. Download enterprise-attack.json (STIX bundle)
  2. Parse groups (intrusion-set), techniques (attack-pattern), malware/tools
  3. Extract CVE references from descriptions + external_references
  4. Walk "uses" relationships: group -> object -> CVEs
  5. Output data/threat_actors.json

Usage:
  python scripts/fetch_threat_actors.py
  python scripts/fetch_threat_actors.py --output data/threat_actors.json
"""

import json, re, os, sys, argparse
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("Missing 'requests'. Run: pip install requests")
    sys.exit(1)

MITRE_URL   = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')


# ─────────────────────────────────────────────
#  DOWNLOAD
# ─────────────────────────────────────────────

def fetch_stix():
    print("[*] Downloading MITRE ATT&CK STIX bundle...")
    resp = requests.get(MITRE_URL, timeout=180, stream=True)
    resp.raise_for_status()
    total = int(resp.headers.get('content-length', 0))
    chunks = []
    received = 0
    for chunk in resp.iter_content(chunk_size=1024 * 1024):
        chunks.append(chunk)
        received += len(chunk)
        if total:
            pct = received / total * 100
            mb  = received / 1024 / 1024
            print(f"\r    {mb:.1f} MB / {total/1024/1024:.1f} MB  ({pct:.0f}%)", end='', flush=True)
    print()
    stix = json.loads(b''.join(chunks))
    print(f"    {len(stix['objects'])} STIX objects loaded")
    return stix


# ─────────────────────────────────────────────
#  CVE EXTRACTION
# ─────────────────────────────────────────────

def extract_cves(obj):
    """Extract all CVE IDs from an object's external_references and description."""
    cves = set()
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'cve':
            eid = ref.get('external_id', '')
            if CVE_PATTERN.match(eid):
                cves.add(eid)
    for field in ('description', 'x_mitre_detection'):
        cves.update(CVE_PATTERN.findall(obj.get(field) or ''))
    return cves


# ─────────────────────────────────────────────
#  MAPPING BUILDER
# ─────────────────────────────────────────────

def build_mapping(stix):
    objects = stix['objects']

    # 1. Collect all groups (intrusion-set)
    groups = {}
    for o in objects:
        if o['type'] != 'intrusion-set':
            continue
        for ref in o.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id', '')
                groups[o['id']] = {
                    'name': o['name'],
                    'id':   mitre_id,
                    'url':  ref.get('url') or f"https://attack.mitre.org/groups/{mitre_id}/",
                }

    # 2. Objects that reference CVEs (attack-pattern, malware, tool, campaign)
    obj_cves = {}
    for o in objects:
        if o['type'] in ('attack-pattern', 'malware', 'tool', 'campaign'):
            cves = extract_cves(o)
            if cves:
                obj_cves[o['id']] = cves

    print(f"    Groups: {len(groups)} | Objects with CVE refs: {len(obj_cves)}")

    # 3. Map campaigns to their attributed groups (attributed-to relationships)
    campaign_groups = {}
    for o in objects:
        if o['type'] == 'relationship' and o.get('relationship_type') == 'attributed-to':
            src, tgt = o.get('source_ref', ''), o.get('target_ref', '')
            if tgt in groups:
                campaign_groups.setdefault(src, []).append(groups[tgt])

    # 4. Walk "uses" relationships to link groups -> CVEs
    cve_actors = {}

    def add_entry(cve, group):
        entry = {'name': group['name'], 'id': group['id'], 'url': group['url']}
        bucket = cve_actors.setdefault(cve, [])
        if entry not in bucket:
            bucket.append(entry)

    for o in objects:
        if o['type'] != 'relationship' or o.get('relationship_type') != 'uses':
            continue
        src, tgt = o.get('source_ref', ''), o.get('target_ref', '')

        # Direct: group uses CVE-bearing technique/malware/tool
        if src in groups and tgt in obj_cves:
            for cve in obj_cves[tgt]:
                add_entry(cve, groups[src])

        # Indirect: campaign uses CVE-bearing object -> credit attributed groups
        if src in campaign_groups and tgt in obj_cves:
            for grp in campaign_groups[src]:
                for cve in obj_cves[tgt]:
                    add_entry(cve, grp)

    # Sort actors alphabetically within each CVE
    for cve in cve_actors:
        cve_actors[cve].sort(key=lambda x: x['name'])

    return cve_actors


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Build CVE->ThreatActor map from MITRE ATT&CK')
    parser.add_argument('--output', default='data/threat_actors.json')
    args = parser.parse_args()

    stix       = fetch_stix()
    cve_actors = build_mapping(stix)

    n_cves     = len(cve_actors)
    n_mappings = sum(len(v) for v in cve_actors.values())

    output = {
        'metadata': {
            'source':           'MITRE ATT&CK Enterprise',
            'lastFetched':      datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'cvesWithActors':   n_cves,
            'totalMappings':    n_mappings,
        },
        'data': cve_actors,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(output, f, separators=(',', ':'))

    print(f"\n[+] Done -> {args.output}")
    print(f"    CVEs with actor attribution : {n_cves}")
    print(f"    Total CVE-actor mappings    : {n_mappings}")


if __name__ == '__main__':
    main()
