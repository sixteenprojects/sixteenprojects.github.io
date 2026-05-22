#!/usr/bin/env python3
"""
Build CVE -> Threat Actor attribution map from MITRE ATT&CK STIX data.
Source: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

Approach:
  1. Download enterprise-attack.json (STIX bundle)
  2. Parse all intrusion-set groups
  3. Walk "uses" relationships:
     - CVEs are extracted from the RELATIONSHIP object's own description
       (e.g. "APT41 exploited CVE-2021-44228...") — these are group-specific.
     - Also include CVEs from malware/tool external_references (source_name='cve'),
       which are explicit structured attributions for that software.
     - Technique (attack-pattern) descriptions are intentionally ignored:
       they describe generic examples and would falsely credit every group
       that uses the technique.
  4. Follow campaign -> attributed-to -> group chains
  5. Output data/threat_actors.json

Usage:
  python scripts/fetch_threat_actors.py
  python scripts/fetch_threat_actors.py --output data/threat_actors.json
"""

import json, re, os, sys, argparse
from datetime import datetime, timezone
from collections import defaultdict

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
    resp = requests.get(MITRE_URL, timeout=300, stream=True)
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
#  CVE EXTRACTION HELPERS
# ─────────────────────────────────────────────

def cves_from_text(obj):
    """CVEs found by regex in an object's description fields."""
    cves = set()
    for field in ('description', 'x_mitre_description'):
        cves.update(CVE_PATTERN.findall(obj.get(field) or ''))
    return cves

def cves_from_extref(obj):
    """CVEs from structured external_references (source_name='cve') only."""
    cves = set()
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'cve':
            eid = ref.get('external_id', '')
            if CVE_PATTERN.match(eid):
                cves.add(eid)
    return cves


# ─────────────────────────────────────────────
#  MAPPING BUILDER
# ─────────────────────────────────────────────

def build_mapping(stix):
    objects = stix['objects']
    idx     = {o['id']: o for o in objects}

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

    print(f"    Groups: {len(groups)}")

    # 2. Campaign -> attributed group chains
    campaign_groups = defaultdict(list)
    for o in objects:
        if o['type'] == 'relationship' and o.get('relationship_type') == 'attributed-to':
            src, tgt = o.get('source_ref', ''), o.get('target_ref', '')
            if tgt in groups:
                campaign_groups[src].append(groups[tgt])

    # 3. Walk "uses" relationships
    #
    #    CVE source (validated against MITRE ATT&CK website):
    #      * relationship description  — e.g. "menuPass used CVE-2020-1472"
    #        This text is written per-group and lives on the relationship object,
    #        not on the technique or group object itself.
    #      * malware/tool external_references with source_name='cve'
    #        Explicit structured association for that specific software.
    #
    #    NOT used:
    #      * technique (attack-pattern) descriptions — generic examples shared
    #        across all groups using the technique (causes false positives).
    #
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
        tgt_obj  = idx.get(tgt, {})
        tgt_type = tgt_obj.get('type', '')

        # Resolve source to group list (direct group or campaign->group)
        src_groups = []
        if src in groups:
            src_groups = [groups[src]]
        elif src in campaign_groups:
            src_groups = campaign_groups[src]

        if not src_groups:
            continue

        # CVEs from the relationship's own description (group-specific usage note)
        rel_cves = cves_from_text(o)

        # CVEs from malware/tool explicit structured external_references
        soft_cves = set()
        if tgt_type in ('malware', 'tool'):
            soft_cves = cves_from_extref(tgt_obj)

        all_cves = rel_cves | soft_cves
        for cve in all_cves:
            for grp in src_groups:
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
            'source':        'MITRE ATT&CK Enterprise',
            'lastFetched':   datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'cvesWithActors': n_cves,
            'totalMappings': n_mappings,
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
