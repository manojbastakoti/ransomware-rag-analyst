"""Data pipeline: curated markdown + MITRE ATT&CK subset -> metadata-rich chunks.

Run:  python -m ransomrag.ingest
Writes data/processed/chunks.jsonl and data/processed/documents.json.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .attack import AttackKB
from .config import ATTACK_SUBSET_PATH, CHUNKS_PATH, DOCS_PATH, RAW_DIR

TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Curated ransomware-core techniques indexed as their own documents (keeps the corpus within the
# 20-50 document scope the brief asks for). Every other technique is still available to the
# checklist tool through the ATT&CK lookup.
CORE_TECHNIQUES = [
    "T1486", "T1490", "T1489", "T1485", "T1529", "T1657",          # impact
    "T1566", "T1190", "T1133", "T1078", "T1189", "T1204.004",      # initial access
    "T1059.001", "T1047", "T1569.002", "T1072",                    # execution
    "T1136.002", "T1068",                                          # persistence / priv-esc
    "T1685", "T1685.005",                                          # defense impairment (ex-T1562.001 / T1070.001)
    "T1003.001", "T1003.003",                                      # credential access
    "T1021.001", "T1219", "T1484.001",                             # lateral movement / C2
    "T1560.001", "T1048", "T1567.002",                             # collection / exfiltration
]
SOFTWARE_PROFILES = ["LockBit 3.0", "BlackCat", "Black Basta", "Akira", "Royal", "Conti", "RansomHub"]


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    title: str
    section: str
    text: str
    source_type: str
    url: str
    actor: str = "generic"
    aliases: list[str] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    advisory_id: str = ""
    published: str = ""
    publisher: str = ""


def parse_front_matter(raw: str) -> tuple[dict, str]:
    if not raw.startswith("---"):
        return {}, raw
    _, fm, body = raw.split("---", 2)
    meta = {}
    for line in fm.strip().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip().strip('"')
    return meta, body


def split_list(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(";") if v.strip()]


def split_sections(body: str) -> list[tuple[str, str]]:
    sections, current, buf = [], "Overview", []
    for line in body.splitlines():
        if line.startswith("## "):
            if "".join(buf).strip():
                sections.append((current, "\n".join(buf).strip()))
            current, buf = line[3:].strip(), []
        elif line.startswith("# ") or line.startswith("> "):
            continue
        else:
            buf.append(line)
    if "".join(buf).strip():
        sections.append((current, "\n".join(buf).strip()))
    return sections


def markdown_chunks(path: Path, kb: AttackKB) -> tuple[dict, list[Chunk]]:
    meta, body = parse_front_matter(path.read_text(encoding="utf-8"))
    doc_id = meta["doc_id"]
    doc = {
        "doc_id": doc_id,
        "title": meta.get("title", doc_id),
        "source_type": meta.get("source_type", "other"),
        "url": meta.get("url", ""),
        "actor": meta.get("actor", "generic"),
        "aliases": split_list(meta.get("aliases", "")),
        "sectors": split_list(meta.get("sectors", "")),
        "advisory_id": meta.get("advisory_id", ""),
        "published": meta.get("published", ""),
        "publisher": meta.get("publisher", ""),
        "path": str(path.relative_to(RAW_DIR.parent.parent)),
    }
    doc_techs: set[str] = set()
    chunks = []
    for i, (section, text) in enumerate(split_sections(body)):
        techs = sorted({kb.normalize_id(t) for t in TID_RE.findall(text)} - {None})
        doc_techs.update(techs)
        chunks.append(
            Chunk(
                chunk_id=f"{doc_id}#{i:02d}",
                doc_id=doc_id,
                title=doc["title"],
                section=section,
                text=text,
                source_type=doc["source_type"],
                url=doc["url"],
                actor=doc["actor"],
                aliases=doc["aliases"],
                sectors=doc["sectors"],
                techniques=techs,
                tactics=kb.tactics_for(techs),
                advisory_id=doc["advisory_id"],
                published=doc["published"],
                publisher=doc["publisher"],
            )
        )
    doc["techniques"] = sorted(doc_techs)
    doc["n_chunks"] = len(chunks)
    return doc, chunks


def technique_chunks(kb: AttackKB, tid: str) -> tuple[dict, list[Chunk]]:
    t = kb.techniques[tid]
    doc_id = f"attack-{tid.lower().replace('.', '-')}"
    legacy = [old for old, new in kb.legacy_map.items() if new == tid]
    title = f"MITRE ATT&CK {tid}: {t['name']}"
    common = dict(
        doc_id=doc_id, title=title, source_type="mitre_technique", url=t["url"] or "",
        techniques=[tid], tactics=t["tactics"], publisher="MITRE ATT&CK",
        advisory_id=tid, published=f"ATT&CK v{kb.version}",
    )
    legacy_note = f" Previously catalogued as {', '.join(legacy)}." if legacy else ""
    overview = (
        f"{tid} {t['name']} (tactics: {', '.join(t['tactics'])}; platforms: {', '.join(t['platforms'])})."
        f"{legacy_note}\n{t['description']}"
    )
    mitig = "\n".join(f"- {m['id']} {m['name']}: {m['how'] or 'See ATT&CK mitigation page.'}" for m in t["mitigations"])
    detect_lines = []
    for d in t["detections"]:
        detect_lines.append(f"- {d['id']} {d['name']}")
        for a in d["analytics"][:2]:
            detect_lines.append(f"  - ({'/'.join(a['platforms'])}) {a['description']} Log sources: {'; '.join(a['log_sources'])}")
    chunks = [Chunk(chunk_id=f"{doc_id}#00", section="Description", text=overview, **common)]
    if mitig:
        chunks.append(Chunk(chunk_id=f"{doc_id}#01", section="Mitigations",
                            text=f"Mitigations for {tid} {t['name']}:\n{mitig}", **common))
    if detect_lines:
        chunks.append(Chunk(chunk_id=f"{doc_id}#02", section="Detection",
                            text=f"Detection strategies for {tid} {t['name']}:\n" + "\n".join(detect_lines), **common))
    doc = {"doc_id": doc_id, "title": title, "source_type": "mitre_technique", "url": t["url"],
           "actor": "generic", "aliases": [], "sectors": [], "advisory_id": tid,
           "published": f"ATT&CK v{kb.version}", "publisher": "MITRE ATT&CK",
           "path": "data/attack/attack_subset.json", "techniques": [tid], "n_chunks": len(chunks)}
    return doc, chunks


def software_chunks(kb: AttackKB, name: str) -> tuple[dict, list[Chunk]]:
    s = kb.software[name]
    doc_id = f"attack-{s['id'].lower()}-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}"
    title = f"MITRE ATT&CK Software {s['id']}: {name}"
    techs = [t["id"] for t in s["techniques"]]
    common = dict(
        doc_id=doc_id, title=title, source_type="mitre_software", url=s["url"] or "", actor=name,
        aliases=s["aliases"], publisher="MITRE ATT&CK", advisory_id=s["id"], published=f"ATT&CK v{kb.version}",
    )
    chunks = [Chunk(chunk_id=f"{doc_id}#00", section="Profile",
                    text=f"{name} ({s['id']}; aliases: {', '.join(s['aliases']) or 'none'}). {s['description']}",
                    techniques=[], tactics=[], **common)]
    # group techniques into chunks of ~10 for retrievability
    for j in range(0, len(s["techniques"]), 10):
        part = s["techniques"][j:j + 10]
        ids = [t["id"] for t in part]
        lines = "\n".join(f"- {t['id']} {t['name']}: {t['how']}" for t in part)
        chunks.append(Chunk(chunk_id=f"{doc_id}#{j // 10 + 1:02d}", section=f"Techniques used ({j + 1}-{j + len(part)})",
                            text=f"Techniques used by {name}:\n{lines}", techniques=ids,
                            tactics=kb.tactics_for(ids), **common))
    doc = {"doc_id": doc_id, "title": title, "source_type": "mitre_software", "url": s["url"], "actor": name,
           "aliases": s["aliases"], "sectors": [], "advisory_id": s["id"], "published": f"ATT&CK v{kb.version}",
           "publisher": "MITRE ATT&CK", "path": "data/attack/attack_subset.json", "techniques": techs,
           "n_chunks": len(chunks)}
    return doc, chunks


def build_corpus() -> tuple[list[dict], list[Chunk]]:
    kb = AttackKB.load(ATTACK_SUBSET_PATH)
    docs, chunks = [], []
    for path in sorted(RAW_DIR.rglob("*.md")):
        d, c = markdown_chunks(path, kb)
        docs.append(d)
        chunks.extend(c)
    for tid in CORE_TECHNIQUES:
        if tid in kb.techniques:
            d, c = technique_chunks(kb, tid)
            docs.append(d)
            chunks.extend(c)
    for name in SOFTWARE_PROFILES:
        if name in kb.software:
            d, c = software_chunks(kb, name)
            docs.append(d)
            chunks.extend(c)
    return docs, chunks


def main() -> None:
    docs, chunks = build_corpus()
    CHUNKS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CHUNKS_PATH.open("w", encoding="utf-8") as fh:
        for c in chunks:
            fh.write(json.dumps(asdict(c)) + "\n")
    DOCS_PATH.write_text(json.dumps(docs, indent=1), encoding="utf-8")
    by_type: dict[str, int] = {}
    for d in docs:
        by_type[d["source_type"]] = by_type.get(d["source_type"], 0) + 1
    print(f"Wrote {len(docs)} documents ({by_type}) and {len(chunks)} chunks -> {CHUNKS_PATH}")


def load_chunks(path: Path = CHUNKS_PATH) -> list[dict]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_documents(path: Path = DOCS_PATH) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
