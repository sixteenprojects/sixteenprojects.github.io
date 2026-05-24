"""
fetch_all.py
Orchestrator — runs all fetchers, validates schemas, writes JSON output.
Run: python fetch_all.py
Output: ../data/malware.json, actors.json, ransomware.json, victims.json, meta.json
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from fetch_malpedia import fetch_families, fetch_actors
from fetch_ransomwarelive import fetch_groups, fetch_victims, enrich_group_victim_counts
from fetch_ransomlook import fetch_groups as rl_fetch_groups, fetch_posts, merge_with_ransomwarelive

DATA_DIR = Path(__file__).parent.parent / "data"
logging.basicConfig(level=logging.INFO, format="%(asctime)s [Orchestrator] %(message)s")
log = logging.getLogger(__name__)


# ── Schema validators ────────────────────────────────────────────────────────

def _validate_malware(items: list) -> list:
    required = {"id", "name", "platform", "type"}
    valid = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if not required.issubset(item.keys()):
            continue
        if not item.get("id") or not item.get("name"):
            continue
        valid.append(item)
    log.info(f"Schema validation: {len(valid)}/{len(items)} malware entries valid")
    return valid


def _validate_actors(items: list) -> list:
    required = {"id", "name"}
    valid = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if not required.issubset(item.keys()):
            continue
        if not item.get("id") or not item.get("name"):
            continue
        valid.append(item)
    log.info(f"Schema validation: {len(valid)}/{len(items)} actor entries valid")
    return valid


def _validate_ransomware(items: list) -> list:
    required = {"id", "name"}
    valid = [
        item for item in items
        if isinstance(item, dict) and item.get("id") and item.get("name")
    ]
    log.info(f"Schema validation: {len(valid)}/{len(items)} ransomware group entries valid")
    return valid


def _validate_victims(items: list) -> list:
    required = {"victim", "group"}
    valid = [
        item for item in items
        if isinstance(item, dict) and item.get("victim") and item.get("group")
    ]
    # Deduplicate by victim+group combination
    seen = set()
    deduped = []
    for v in valid:
        key = f"{v['group']}:{v['victim']}"
        if key not in seen:
            seen.add(key)
            deduped.append(v)
    log.info(f"Schema validation: {len(deduped)} unique victims (from {len(items)} raw)")
    return deduped


# ── Write helpers ─────────────────────────────────────────────────────────────

def _write_json(filename: str, data: list | dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    size_kb = path.stat().st_size / 1024
    log.info(f"Written: {path} ({size_kb:.1f} KB)")


def _load_existing(filename: str) -> list | dict | None:
    path = DATA_DIR / filename
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


# ── Main orchestration ────────────────────────────────────────────────────────

def run_all(skip_malpedia: bool = False, skip_ransomware: bool = False) -> dict:
    start = time.time()
    status: dict[str, dict] = {}

    # ── Malpedia ──
    if not skip_malpedia:
        try:
            log.info("=== Starting Malpedia fetch ===")
            families = fetch_families()
            actors = fetch_actors()

            families = _validate_malware(families)
            actors = _validate_actors(actors)

            _write_json("malware.json", families)
            _write_json("actors.json", actors)

            status["malpedia"] = {
                "status": "ok",
                "malware_count": len(families),
                "actor_count": len(actors),
                "fetched_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            log.error(f"Malpedia fetch failed: {e}")
            status["malpedia"] = {"status": "error", "error": str(e)}
    else:
        log.info("Skipping Malpedia (--skip-malpedia)")
        existing_m = _load_existing("malware.json") or []
        existing_a = _load_existing("actors.json") or []
        status["malpedia"] = {"status": "skipped",
                              "malware_count": len(existing_m),
                              "actor_count": len(existing_a)}

    # ── Ransomware.live ──
    if not skip_ransomware:
        try:
            log.info("=== Starting Ransomware.live fetch ===")
            rw_groups = fetch_groups()
            victims = fetch_victims()

            # RansomLook enrichment
            try:
                log.info("=== Starting RansomLook enrichment ===")
                rl_groups = rl_fetch_groups()
                if rl_groups:
                    rw_groups = merge_with_ransomwarelive(rw_groups, rl_groups)
                    log.info(f"Merged {len(rl_groups)} RansomLook groups")
                    status["ransomlook"] = {
                        "status": "ok",
                        "groups_merged": len(rl_groups),
                        "fetched_at": datetime.now(timezone.utc).isoformat()
                    }
                else:
                    status["ransomlook"] = {"status": "no_data"}
            except Exception as e:
                log.warning(f"RansomLook enrichment failed: {e}")
                status["ransomlook"] = {"status": "error", "error": str(e)}

            # Enrich victim counts per group
            rw_groups = enrich_group_victim_counts(rw_groups, victims)

            rw_groups = _validate_ransomware(rw_groups)
            victims = _validate_victims(victims)

            _write_json("ransomware.json", rw_groups)
            _write_json("victims.json", victims)

            status["ransomware_live"] = {
                "status": "ok",
                "group_count": len(rw_groups),
                "victim_count": len(victims),
                "fetched_at": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            log.error(f"Ransomware.live fetch failed: {e}")
            status["ransomware_live"] = {"status": "error", "error": str(e)}
    else:
        log.info("Skipping Ransomware (--skip-ransomware)")
        existing_rw = _load_existing("ransomware.json") or []
        existing_v = _load_existing("victims.json") or []
        status["ransomware_live"] = {"status": "skipped",
                                     "group_count": len(existing_rw),
                                     "victim_count": len(existing_v)}

    # ── Write meta ──
    elapsed = round(time.time() - start, 1)
    meta = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "counts": {
            "malware": status.get("malpedia", {}).get("malware_count", 0),
            "actors": status.get("malpedia", {}).get("actor_count", 0),
            "ransomware_groups": status.get("ransomware_live", {}).get("group_count", 0),
            "victims": status.get("ransomware_live", {}).get("victim_count", 0)
        },
        "sources": status
    }
    _write_json("meta.json", meta)

    log.info(f"=== All done in {elapsed}s ===")
    log.info(f"  Malware:   {meta['counts']['malware']}")
    log.info(f"  Actors:    {meta['counts']['actors']}")
    log.info(f"  RW Groups: {meta['counts']['ransomware_groups']}")
    log.info(f"  Victims:   {meta['counts']['victims']}")
    return meta


if __name__ == "__main__":
    skip_malpedia = "--skip-malpedia" in sys.argv
    skip_ransomware = "--skip-ransomware" in sys.argv
    run_all(skip_malpedia=skip_malpedia, skip_ransomware=skip_ransomware)
