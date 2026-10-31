"""Safety controls: input validation, offensive-use refusal, prompt-injection screening,
retrieved-context sanitisation and citation verification (OWASP LLM01/LLM02/LLM09 aligned)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import MAX_QUERY_CHARS

OFFENSIVE_PATTERNS = [
    r"\b(write|create|build|develop|code|generate|make)\b.{0,40}\b(ransomware|malware|encryptor|locker|payload|virus|worm|keylogger|stealer|dropper|loader)\b",
    r"\b(bypass|evade|disable|kill|avoid)\b.{0,30}\b(edr|antivirus|defender|av|detection|security tools?)\b.{0,40}\b(without|undetected|so (that )?(i|we) can|to deploy|to run|to spread)\b",
    r"\bhow (do|can|to|would) (i|we|you)\b.{0,40}\b(deploy|spread|launch|infect|encrypt)\b.{0,40}\b(ransomware|victims?|network|company|hospital)\b",
    r"\b(exploit|weaponi[sz]e)\b.{0,40}\b(cve-\d{4}-\d+)\b.{0,40}\b(code|poc|script|payload)\b",
    r"\b(working|functional|full)\b.{0,20}\b(exploit|poc)\b",
    r"\bransom note\b.{0,30}\b(write|draft|create)\b|\b(write|draft|create)\b.{0,30}\bransom note\b",
    r"\b(launder|cash ?out|mix)\b.{0,30}\b(ransom|bitcoin|crypto)\b",
]

INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?)",
    r"disregard (the |all )?(system|previous) (prompt|instructions)",
    r"you are now\b", r"reveal (your )?(system prompt|instructions)", r"\bdeveloper mode\b",
    r"act as (an? )?(unfiltered|jailbroken)", r"<\s*/?\s*system\s*>",
]


@dataclass
class GuardResult:
    allowed: bool
    query: str
    warnings: list[str] = field(default_factory=list)
    refusal: str = ""


REFUSAL = (
    "This assistant supports **defensive** ransomware analysis only. I can't help build, deploy or "
    "evade detection for malware. I can instead explain how this behaviour is detected and mitigated — "
    "try asking e.g. *'How do we detect and contain attempts to disable EDR?'*"
)


def check_query(query: str) -> GuardResult:
    q = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", query or "").strip()
    if not q:
        return GuardResult(False, q, refusal="Please enter a question about ransomware threats or defences.")
    warnings = []
    if len(q) > MAX_QUERY_CHARS:
        q = q[:MAX_QUERY_CHARS]
        warnings.append(f"Question truncated to {MAX_QUERY_CHARS} characters.")
    low = q.lower()
    if any(re.search(p, low) for p in OFFENSIVE_PATTERNS):
        return GuardResult(False, q, warnings, REFUSAL)
    if any(re.search(p, low) for p in INJECTION_PATTERNS):
        warnings.append("Possible prompt-injection phrasing detected in the question; it was neutralised and "
                        "the assistant kept its defensive instructions.")
        for p in INJECTION_PATTERNS:
            q = re.sub(p, "[removed]", q, flags=re.I)
    return GuardResult(True, q, warnings)


def sanitize_context(text: str) -> str:
    """Drop instruction-like lines from retrieved documents before they reach the LLM (RAG poisoning)."""
    kept = [ln for ln in text.splitlines() if not any(re.search(p, ln.lower()) for p in INJECTION_PATTERNS)]
    return "\n".join(kept)


CITE_RE = re.compile(r"\[(S\d+)\]")


def verify_citations(answer: str, valid_refs: set[str]) -> tuple[str, dict]:
    """Remove citations that point to sources that were not retrieved; report citation stats."""
    cited = CITE_RE.findall(answer)
    invalid = sorted({c for c in cited if c not in valid_refs})
    for ref in invalid:
        answer = answer.replace(f"[{ref}]", "")
    valid_cited = [c for c in cited if c in valid_refs]
    return answer, {
        "n_citations": len(cited),
        "n_valid": len(valid_cited),
        "invalid_refs": invalid,
        "unique_sources_cited": sorted(set(valid_cited), key=lambda r: int(r[1:])),
        "grounded": len(valid_cited) > 0,
    }
