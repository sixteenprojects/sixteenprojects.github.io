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
from fetch_ransomwarelive import (
    fetch_groups, fetch_victims, enrich_group_victim_counts,
    fetch_sectors, fetch_recent_attacks
)
from fetch_ransomlook import (
    fetch_groups as rl_fetch_groups, fetch_posts, merge_with_ransomwarelive,
    fetch_stats as rl_fetch_stats, fetch_recent as rl_fetch_recent
)
from fetch_mitre import enrich_malware_list

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


def _cross_ref_actor_malware(families: list, actors: list) -> list:
    """Populate actor.malware by building reverse index from malware.actors."""
    # Build: actor_name_lower → list of malware ids
    index: dict[str, list] = {}
    for fam in families:
        for actor_ref in fam.get("actors", []):
            key = actor_ref.lower().strip()
            if key:
                index.setdefault(key, []).append(fam["id"])

    enriched = 0
    for actor in actors:
        search_keys = set()
        search_keys.add(actor.get("name", "").lower())
        search_keys.add(actor.get("id", "").lower())
        for alias in actor.get("aliases", []):
            search_keys.add(alias.lower())

        malware_ids: list[str] = []
        for key in search_keys:
            if key in index:
                malware_ids.extend(index[key])

        malware_ids = list(dict.fromkeys(malware_ids))[:50]
        if malware_ids:
            actor["malware"] = malware_ids
            enriched += 1

    log.info(f"Cross-reference: populated malware list for {enriched}/{len(actors)} actors")
    return actors


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


# ── Stats computation ─────────────────────────────────────────────────────────

def _compute_stats(victims: list, ransomware: list, sectors_raw: dict,
                   rl_stats: dict, recent_attacks: list) -> dict:
    """Compute comprehensive statistics from victims and group data."""
    monthly: dict[str, int] = {}
    yearly: dict[str, int] = {}
    country_counts: dict[str, int] = {}
    stealer_counts: dict[str, int] = {}
    total_employees = 0
    total_users = 0
    victims_with_stealer = 0
    this_year = datetime.now(timezone.utc).year
    this_month = f"{this_year}-{datetime.now(timezone.utc).month:02d}"
    victims_this_year = 0
    victims_this_month = 0

    for v in victims:
        date_str = v.get("attack_date") or v.get("discovered") or ""
        try:
            d = datetime.fromisoformat(date_str[:10])
            mo = f"{d.year}-{d.month:02d}"
            monthly[mo] = monthly.get(mo, 0) + 1
            yearly[str(d.year)] = yearly.get(str(d.year), 0) + 1
            if d.year == this_year:
                victims_this_year += 1
            if mo == this_month:
                victims_this_month += 1
        except Exception:
            pass

        c = (v.get("country") or "").upper()[:2]
        if c and c != "??":
            country_counts[c] = country_counts.get(c, 0) + 1

        is_data = v.get("infostealer") or {}
        if isinstance(is_data, dict):
            stealers = is_data.get("stealers") or {}
            if isinstance(stealers, dict) and stealers:
                victims_with_stealer += 1
                total_employees += int(is_data.get("employees") or 0)
                total_users += int(is_data.get("users") or 0)
                for sname, scount in stealers.items():
                    stealer_counts[sname] = stealer_counts.get(sname, 0) + int(scount or 0)

    # Top groups by victim count (exclude unnamed/unknown entries)
    top_groups = sorted(
        [{"name": g["name"], "id": g["id"], "count": g.get("victim_count", 0),
          "status": g.get("status", "unknown"), "is_raas": g.get("is_raas", False)}
         for g in ransomware
         if g.get("id", "unknown") not in ("unknown", "") and g.get("name", "unknown").lower() != "unknown"],
        key=lambda x: x["count"], reverse=True
    )[:20]

    # Sort monthly/yearly
    monthly_sorted = [{"month": k, "count": monthly[k]} for k in sorted(monthly.keys())]
    yearly_sorted = {k: yearly[k] for k in sorted(yearly.keys())}
    country_sorted = dict(sorted(country_counts.items(), key=lambda x: x[1], reverse=True))
    stealer_sorted = dict(sorted(stealer_counts.items(), key=lambda x: x[1], reverse=True)[:30])

    active_groups = sum(1 for g in ransomware if g.get("status") == "active")
    raas_groups = sum(1 for g in ransomware if g.get("is_raas"))

    return {
        "overview": {
            "total_victims": len(victims),
            "victims_this_year": victims_this_year,
            "victims_this_month": victims_this_month,
            "total_groups": len(ransomware),
            "active_groups": active_groups,
            "raas_groups": raas_groups,
            "countries_hit": len(country_counts),
            "victims_with_infostealer": victims_with_stealer,
            "infostealer_employees_exposed": total_employees,
            "infostealer_users_exposed": total_users,
        },
        "sectors": sectors_raw or {},
        "countries": country_sorted,
        "monthly": monthly_sorted,
        "yearly": yearly_sorted,
        "top_groups": top_groups,
        "infostealer": {
            "with_stealer": victims_with_stealer,
            "total": len(victims),
            "stealers": stealer_sorted,
            "total_employees": total_employees,
            "total_users": total_users,
        },
        "ransomlook": rl_stats,
        "recent_attacks": recent_attacks[:50],
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


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

            # Enrich missing descriptions from MITRE ATT&CK
            try:
                families = enrich_malware_list(families)
                log.info("MITRE ATT&CK enrichment applied to malware families")
            except Exception as e:
                log.warning(f"MITRE enrichment failed: {e}")

            # Cross-reference: populate actor.malware from malware.actors
            actors = _cross_ref_actor_malware(families, actors)

            families = _validate_malware(families)
            actors   = _validate_actors(actors)

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
    sectors_raw: dict = {}
    recent_attacks: list = []
    rl_stats: dict = {}

    if not skip_ransomware:
        try:
            log.info("=== Starting Ransomware.live fetch ===")
            rw_groups = fetch_groups()
            victims = fetch_victims()

            # Sector stats
            try:
                sectors_raw = fetch_sectors()
                log.info(f"Fetched {len(sectors_raw)} sectors from ransomware.live")
            except Exception as e:
                log.warning(f"Sector fetch failed: {e}")

            # Recent attacks
            try:
                recent_attacks = fetch_recent_attacks()
                log.info(f"Fetched {len(recent_attacks)} recent attacks")
            except Exception as e:
                log.warning(f"Recent attacks fetch failed: {e}")

            # RansomLook enrichment
            try:
                log.info("=== Starting RansomLook enrichment ===")
                rl_groups = rl_fetch_groups()
                rl_stats = rl_fetch_stats()
                if rl_stats:
                    log.info(f"RansomLook stats: {rl_stats}")
                if rl_groups:
                    rw_groups = merge_with_ransomwarelive(rw_groups, rl_groups)
                    log.info(f"Merged {len(rl_groups)} RansomLook groups")
                    status["ransomlook"] = {
                        "status": "ok",
                        "groups_merged": len(rl_groups),
                        "stats": rl_stats,
                        "fetched_at": datetime.now(timezone.utc).isoformat()
                    }
                else:
                    status["ransomlook"] = {"status": "no_data"}
            except Exception as e:
                log.warning(f"RansomLook enrichment failed: {e}")
                status["ransomlook"] = {"status": "error", "error": str(e)}

            # RansomLook recent posts (supplement recent_attacks)
            try:
                rl_recent = rl_fetch_recent(30)
                log.info(f"Fetched {len(rl_recent)} RansomLook recent posts")
                # Append unique ones not already in recent_attacks
                existing_victims = {r.get("victim", "").lower() for r in recent_attacks}
                for r in rl_recent:
                    if r.get("victim", "").lower() not in existing_victims:
                        recent_attacks.append(r)
                        existing_victims.add(r.get("victim", "").lower())
            except Exception as e:
                log.warning(f"RansomLook recent fetch failed: {e}")

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

            # Write computed stats
            stats_data = _compute_stats(victims, rw_groups, sectors_raw, rl_stats, recent_attacks)
            _write_json("stats.json", stats_data)
            _write_json("recent.json", recent_attacks[:100])

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
