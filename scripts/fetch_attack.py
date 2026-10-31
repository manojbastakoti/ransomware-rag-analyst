"""Download MITRE ATT&CK Enterprise STIX data and extract a ransomware-focused subset.

Usage:
    python scripts/fetch_attack.py                 # download from GitHub
    python scripts/fetch_attack.py --local enterprise-attack.json

Output: data/attack/attack_subset.json (committed to the repo so the app runs offline).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ransomrag.config import ATTACK_SUBSET_PATH, RAW_DIR  # noqa: E402

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Ransomware software profiles to include as corpus documents.
SOFTWARE = ["LockBit 3.0", "BlackCat", "Black Basta", "Akira", "Royal", "Conti", "RansomHub"]

TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\((?:https?://)[^)]+\)", r"\1", text)
    text = re.sub(r"<code>|</code>", "`", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def ext_url(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url")
    return None


def techniques_in_corpus() -> set[str]:
    ids: set[str] = set()
    for md in RAW_DIR.rglob("*.md"):
        ids.update(TID_RE.findall(md.read_text(encoding="utf-8")))
    return ids


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", help="Path to a local enterprise-attack.json")
    args = ap.parse_args()

    if args.local:
        bundle = json.loads(Path(args.local).read_text(encoding="utf-8"))
    else:
        import requests

        print(f"Downloading {STIX_URL} ...")
        resp = requests.get(STIX_URL, timeout=120)
        resp.raise_for_status()
        bundle = resp.json()

    all_objs = bundle["objects"]
    all_by_ref = {o["id"]: o for o in all_objs}
    objs = [o for o in all_objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_ref = {o["id"]: o for o in objs}

    # Legacy technique IDs (e.g. T1562.001 in older advisories) -> current IDs (ATT&CK v19+ renumbering)
    legacy_map: dict[str, str] = {}
    for r in all_objs:
        if r.get("type") == "relationship" and r.get("relationship_type") == "revoked-by":
            src, tgt = all_by_ref.get(r["source_ref"]), all_by_ref.get(r["target_ref"])
            if src and tgt and src.get("type") == "attack-pattern" and ext_id(src) and ext_id(tgt):
                legacy_map[ext_id(src)] = ext_id(tgt)
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "unknown")

    techniques = {ext_id(o): o for o in objs if o["type"] == "attack-pattern" and ext_id(o)}
    rels = [o for o in objs if o["type"] == "relationship"]

    mitigates: dict[str, list] = {}
    detects: dict[str, list] = {}
    uses: dict[str, list] = {}
    for r in rels:
        src, tgt = by_ref.get(r["source_ref"]), by_ref.get(r["target_ref"])
        if not src or not tgt:
            continue
        if r["relationship_type"] == "mitigates" and tgt["type"] == "attack-pattern":
            mitigates.setdefault(tgt["id"], []).append((src, r.get("description", "")))
        elif r["relationship_type"] == "detects" and tgt["type"] == "attack-pattern":
            detects.setdefault(tgt["id"], []).append(src)
        elif r["relationship_type"] == "uses" and tgt["type"] == "attack-pattern":
            uses.setdefault(src["id"], []).append((tgt, r.get("description", "")))

    wanted = {legacy_map.get(t, t) for t in techniques_in_corpus()}
    # Always include parents of sub-techniques
    wanted |= {t.split(".")[0] for t in wanted}

    def technique_record(tid: str) -> dict | None:
        o = techniques.get(tid)
        if not o:
            return None
        mits = mitigates.get(o["id"], [])
        if not mits and "." in tid and tid.split(".")[0] in techniques:
            mits = mitigates.get(techniques[tid.split(".")[0]]["id"], [])
        dets = []
        for ds in detects.get(o["id"], []):
            analytics = []
            for aref in ds.get("x_mitre_analytic_refs", [])[:3]:
                an = by_ref.get(aref)
                if not an:
                    continue
                analytics.append(
                    {
                        "platforms": an.get("x_mitre_platforms", []),
                        "description": clean(an.get("description", ""))[:600],
                        "log_sources": [
                            f"{ls.get('name')} ({ls.get('channel')})"
                            for ls in an.get("x_mitre_log_source_references", [])[:4]
                        ],
                    }
                )
            dets.append({"id": ext_id(ds), "name": ds.get("name"), "analytics": analytics})
        return {
            "id": tid,
            "name": o["name"],
            "url": ext_url(o),
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])],
            "platforms": o.get("x_mitre_platforms", []),
            "description": clean(o.get("description", ""))[:1500],
            "mitigations": [
                {"id": ext_id(m), "name": m["name"], "how": clean(desc)[:400]}
                for m, desc in mits
                if ext_id(m)
            ],
            "detections": dets,
        }

    out_tech = {}
    for tid in sorted(wanted):
        rec = technique_record(tid)
        if rec:
            out_tech[tid] = rec
        else:
            print(f"  note: {tid} not found in ATT&CK v{version} (renamed or tactic id)")

    software = {}
    sw_objs = [o for o in objs if o["type"] in ("malware", "tool")]
    for name in SOFTWARE:
        o = next((s for s in sw_objs if s["name"] == name), None)
        if not o:
            print(f"  note: software {name} not found")
            continue
        techs = []
        for t, desc in uses.get(o["id"], []):
            tid = ext_id(t)
            if tid:
                techs.append({"id": tid, "name": t["name"], "how": clean(desc)[:300]})
                if tid not in out_tech:
                    rec = technique_record(tid)
                    if rec:
                        out_tech[tid] = rec
        software[name] = {
            "id": ext_id(o),
            "name": name,
            "url": ext_url(o),
            "aliases": [a for a in o.get("x_mitre_aliases", []) if a != name],
            "description": clean(o.get("description", ""))[:1500],
            "techniques": sorted(techs, key=lambda x: x["id"]),
        }

    ATTACK_SUBSET_PATH.parent.mkdir(parents=True, exist_ok=True)
    ATTACK_SUBSET_PATH.write_text(
        json.dumps(
            {
                "attack_version": version,
                "source": STIX_URL,
                "legacy_id_map": {k: v for k, v in sorted(legacy_map.items()) if v in out_tech},
                "techniques": out_tech,
                "software": software,
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    print(f"ATT&CK v{version}: wrote {len(out_tech)} techniques and {len(software)} software profiles "
          f"to {ATTACK_SUBSET_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
