"""MITRE ATT&CK knowledge base (offline subset extracted by scripts/fetch_attack.py)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .config import ATTACK_SUBSET_PATH

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "stealth", "defense-impairment", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


@dataclass
class AttackKB:
    version: str
    techniques: dict
    software: dict
    legacy_map: dict

    @classmethod
    def load(cls, path: Path = ATTACK_SUBSET_PATH) -> "AttackKB":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(d["attack_version"], d["techniques"], d["software"], d.get("legacy_id_map", {}))

    def normalize_id(self, tid: str) -> str | None:
        """Map legacy IDs (e.g. T1562.001 from 2023 advisories) to the current ATT&CK ID."""
        tid = tid.strip().upper()
        tid = self.legacy_map.get(tid, tid)
        if tid in self.techniques:
            return tid
        parent = tid.split(".")[0]
        parent = self.legacy_map.get(parent, parent)
        return parent if parent in self.techniques else None

    def get(self, tid: str) -> dict | None:
        nid = self.normalize_id(tid)
        return self.techniques.get(nid) if nid else None

    def tactics_for(self, tids: list[str]) -> list[str]:
        tactics = {t for tid in tids if (rec := self.get(tid)) for t in rec["tactics"]}
        return sorted(tactics, key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)

    @staticmethod
    def tactic_rank(tactics: list[str]) -> int:
        ranks = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
        return min(ranks) if ranks else 99


@lru_cache(maxsize=1)
def get_kb() -> AttackKB:
    return AttackKB.load()
