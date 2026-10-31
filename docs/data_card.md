# Data card — Ransomware CTI corpus (Group 3B)

| Field | Value |
|---|---|
| Purpose | Retrieval corpus for a defensive ransomware threat-intelligence RAG analyst |
| Scope chosen | **Ransomware behaviour & enterprise readiness**, with healthcare emphasis (Daixin, Black Basta, ALPHV Blackcat, Rhysida, Medusa, Interlock all report healthcare victims) |
| Size | **47 documents → 190 section-level chunks** (brief asks for 20–50 curated documents/sections) |
| Licence / sensitivity | CISA advisories are TLP:CLEAR U.S. government publications; MITRE ATT&CK® is © The MITRE Corporation, used under the ATT&CK terms of use. No personal data. |
| Built | October 2026; ATT&CK Enterprise v20.0 |

## Sources

| Type | Count | Documents |
|---|---|---|
| `cisa_advisory` | 10 | LockBit 3.0 (AA23-075A), ALPHV Blackcat (AA23-353A), Black Basta (AA24-131A), Akira (AA24-109A), Play (AA23-352A), Rhysida (AA23-319A), Medusa (AA25-071A), Ghost/Cring (AA25-050A), Daixin Team (AA22-294A), Interlock (AA25-203A) |
| `playbook` | 2 | CISA Ransomware Response Checklist (#StopRansomware Guide Part 2); Ransomware Prevention Baseline (team synthesis of the advisories' mitigation sections, each control attributed to its advisories) |
| `mitre_technique` | 28 | Ransomware-core techniques (impact, initial access, execution, defense impairment, credential access, lateral movement, exfiltration) with ATT&CK mitigations and detection strategies |
| `mitre_software` | 7 | LockBit 3.0 (S1202), BlackCat (S1068), Black Basta (S1070), Akira (S1129), Royal (S1073), Conti (S0575), RansomHub (S1212) |

The checklist tool can also look up all **145 techniques** referenced by the advisories or software profiles (stored in `data/attack/attack_subset.json`).

## Collection and preprocessing

1. **Advisories** — each advisory was read from its public CISA/IC3 page and written up as a structured markdown summary in `data/raw/advisories/` with YAML-style front matter (doc ID, advisory ID, date, URL, actor, aliases, model, sectors) and fixed sections: Overview, Initial Access, … , Mitigations. Technique IDs are kept inline exactly as the advisory lists them. Summaries paraphrase the advisory; IOCs are intentionally excluded.
2. **ATT&CK** — `scripts/fetch_attack.py` downloads the official STIX bundle from `mitre-attack/attack-stix-data` and extracts techniques, mitigations (`mitigates` relationships), detection strategies/analytics (`detects`), software profiles (`uses`) and a **legacy-ID map** from `revoked-by` relationships. This matters because ATT&CK v19/v20 renumbered several defense-evasion techniques (e.g. **T1562.001 → T1685**, **T1070.001 → T1685.005**) that 2023–2025 advisories still cite.
3. **Chunking** — `ransomrag/ingest.py` splits each document at `##` section headings (mean ≈ 800 characters/chunk), extracts technique IDs, normalises legacy IDs, derives tactics from ATT&CK and attaches metadata.
4. **Indexing** — `scripts/build_index.py` embeds chunks (BAAI/bge-small-en-v1.5 via sentence-transformers when installed; otherwise TF-IDF + LSA, fully offline) and builds a BM25 index with Snowball stemming.

## Chunk schema

| Field | Example |
|---|---|
| `chunk_id` | `cisa-aa24-109a-akira#01` |
| `doc_id`, `title`, `section`, `url` | `…`, `#StopRansomware: Akira Ransomware`, `Initial Access`, `https://www.cisa.gov/…/aa24-109a` |
| `source_type` | `cisa_advisory` · `playbook` · `mitre_technique` · `mitre_software` |
| `actor`, `aliases` | `Akira`, `["Megazord", "Akira_v2"]` |
| `sectors` | `["critical_infrastructure", "multi_sector"]` |
| `techniques`, `tactics` | `["T1078","T1133","T1190","T1566.001"]`, `["initial-access", …]` |
| `advisory_id`, `published`, `publisher` | `AA24-109A`, `2024-04-18`, `FBI, CISA, Europol EC3, NCSC-NL` |

## Known limitations and biases

* U.S.-centric (CISA/FBI) sources; ransomware ecosystems change quickly and some actors (e.g. LockBit, ALPHV) were disrupted after publication.
* Advisory summaries are paraphrases — the original links remain the authoritative source.
* Sector labels come from the advisories' own wording and are coarse.
* The evaluation set was written by the team against this corpus, so scores measure fitness for this scope, not general CTI coverage.

## Reproduce

```bash
python scripts/fetch_attack.py      # optional: refresh ATT&CK (needs internet)
python scripts/build_index.py       # chunks + embeddings + BM25
```
