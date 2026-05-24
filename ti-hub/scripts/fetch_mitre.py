"""
fetch_mitre.py
Downloads MITRE ATT&CK Enterprise STIX data and extracts software (malware/tool)
descriptions and technique mappings. Used to enrich Malpedia entries.
No authentication required.
"""

import requests
import json
import logging
import time
from functools import lru_cache

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
REQUEST_TIMEOUT = 60

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MITRE] %(message)s")
log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _load_stix() -> dict | None:
    log.info("Downloading MITRE ATT&CK STIX bundle...")
    try:
        resp = requests.get(STIX_URL, timeout=REQUEST_TIMEOUT, headers={
            "User-Agent": "TheSixteenProject-TIHub/1.0"
        })
        resp.raise_for_status()
        data = resp.json()
        log.info(f"Downloaded STIX bundle ({len(resp.content)//1024} KB, "
                 f"{len(data.get('objects', []))} objects)")
        return data
    except Exception as e:
        log.error(f"Failed to download MITRE STIX: {e}")
        return None


def fetch_software_descriptions() -> dict[str, dict]:
    """
    Returns a dict keyed by lowercase name (and aliases) mapping to:
      { description, mitre_id, type, aliases }
    Covers malware + tool objects in MITRE ATT&CK.
    """
    stix = _load_stix()
    if not stix:
        return {}

    index: dict[str, dict] = {}

    for obj in stix.get("objects", []):
        obj_type = obj.get("type", "")
        if obj_type not in ("malware", "tool"):
            continue

        name = obj.get("name", "").strip()
        if not name:
            continue

        description = (obj.get("description") or "").strip()
        import re
        # Remove citation markers: (Citation: ...)
        description = re.sub(r'\(Citation:[^)]+\)', '', description)
        # Convert markdown links [text](url) → text
        description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)
        # Clean up extra whitespace
        description = re.sub(r'\s{2,}', ' ', description).strip()

        aliases = [a for a in obj.get("aliases", []) if a and a != name]
        x_aliases = obj.get("x_mitre_aliases", [])
        if isinstance(x_aliases, list):
            aliases += [a for a in x_aliases if a and a != name]
        aliases = list(dict.fromkeys(aliases))  # deduplicate, preserve order

        # Find MITRE ID (e.g., S0154)
        mitre_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                break

        entry = {
            "description": description[:1000],
            "mitre_id": mitre_id,
            "type": obj_type,
            "aliases": aliases[:10],
        }

        # Index by name and all aliases (lowercase)
        for key in [name] + aliases:
            index[key.lower()] = entry

    log.info(f"Indexed {len(index)} MITRE software name/alias keys "
             f"from {sum(1 for o in stix['objects'] if o.get('type') in ('malware','tool'))} software objects")
    return index


def enrich_malware_list(malware_list: list[dict]) -> list[dict]:
    """
    Fill missing descriptions and augment aliases in Malpedia malware entries
    using MITRE ATT&CK data. Only fills fields that are currently empty.
    """
    index = fetch_software_descriptions()
    if not index:
        log.warning("No MITRE data available — skipping enrichment")
        return malware_list

    enriched = 0
    for item in malware_list:
        if item.get("description"):
            continue  # already has description, don't overwrite

        # Try matching by name, then aliases
        search_keys = [item.get("name", "").lower()]
        for alias in item.get("aliases", []):
            search_keys.append(alias.lower())
        # Also try last segment of malpedia id (e.g. "win.emotet" -> "emotet")
        item_id = item.get("id", "")
        if "." in item_id:
            search_keys.append(item_id.split(".")[-1].replace("_", " "))

        for key in search_keys:
            if key in index:
                mitre = index[key]
                if mitre["description"]:
                    item["description"] = f"[MITRE ATT&CK] {mitre['description']}"
                if mitre["mitre_id"] and not item.get("mitre_id"):
                    item["mitre_id"] = mitre["mitre_id"]
                # Merge aliases
                existing = set(a.lower() for a in item.get("aliases", []))
                for alias in mitre["aliases"]:
                    if alias.lower() not in existing:
                        item.setdefault("aliases", []).append(alias)
                enriched += 1
                break

    log.info(f"MITRE enrichment: filled descriptions for {enriched} malware entries")
    return malware_list
