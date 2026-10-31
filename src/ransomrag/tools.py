"""Agent tools. Each tool is a plain Python function returning JSON-serialisable output, so the agent
(LLM-driven or rule-based) can call it and the UI can display exactly what each tool returned."""
from __future__ import annotations

import re
from collections import defaultdict

from .attack import AttackKB, get_kb
from .config import TOP_K
from .guardrails import sanitize_context
from .vectorstore import Hit, VectorIndex, get_index

# --------------------------------------------------------------------------------------------------
# Tool 1: search_ransomware_intel
# --------------------------------------------------------------------------------------------------


def search_ransomware_intel(query: str, k: int = TOP_K, actor: str | None = None, sector: str | None = None,
                            technique: str | None = None, source_type: str | None = None,
                            index: VectorIndex | None = None) -> list[Hit]:
    """Hybrid semantic + keyword search over the ransomware corpus with metadata filters."""
    index = index or get_index()
    filters = {"actor": actor, "sector": sector, "technique": technique, "source_type": source_type}
    return index.search(query, k=k, filters=filters)


# --------------------------------------------------------------------------------------------------
# Tool 2: map_attack_techniques
# --------------------------------------------------------------------------------------------------


# Behaviour keywords an analyst may state directly in the question ("our files are encrypted").
QUERY_TECHNIQUE_HINTS = [
    (r"\bencrypt", "T1486"), (r"shadow cop|vssadmin|backups? (deleted|wiped)", "T1490"),
    (r"rclone|megasync|mega\.nz|cloud storage", "T1567.002"), (r"\brdp\b|remote desktop", "T1021.001"),
    (r"phish", "T1566"), (r"\bvpn\b", "T1133"), (r"anydesk|\brmm\b|remote (access|monitoring) (tool|software)", "T1219"),
    (r"\bedr\b|antivirus|defender", "T1685"), (r"lsass|mimikatz|credential dump", "T1003.001"),
    (r"psexec", "T1569.002"), (r"powershell", "T1059.001"), (r"esxi|hypervisor|virtual machines?", "T1529"),
]
SOURCE_WEIGHT = {"cisa_advisory": 1.0, "playbook": 1.0, "mitre_technique": 0.9, "mitre_software": 0.6}


def techniques_from_query(query: str) -> list[str]:
    q = (query or "").lower()
    return [tid for pat, tid in QUERY_TECHNIQUE_HINTS if re.search(pat, q)]


def map_attack_techniques(hits: list[Hit], kb: AttackKB | None = None, max_items: int = 15,
                          query: str | None = None) -> list[dict]:
    """Aggregate ATT&CK techniques evidenced by the retrieved chunks (and behaviours the analyst stated
    in the question), ordered along the kill chain."""
    kb = kb or get_kb()
    weight: dict[str, float] = defaultdict(float)
    refs: dict[str, list[str]] = defaultdict(list)
    for h in hits:
        n = max(len(h.chunk["techniques"]), 1)
        w = max(h.score, 0.01) * SOURCE_WEIGHT.get(h.chunk["source_type"], 1.0) / (n ** 0.5)
        for tid in h.chunk["techniques"]:
            nid = kb.normalize_id(tid)
            if not nid:
                continue
            weight[nid] += w
            if h.ref not in refs[nid]:
                refs[nid].append(h.ref)
    for tid in techniques_from_query(query or ""):
        nid = kb.normalize_id(tid)
        if nid:
            weight[nid] += 1.0
            refs[nid].append("question")
    rows = []
    for tid, w in weight.items():
        rec = kb.techniques[tid]
        rows.append({
            "id": tid, "name": rec["name"], "tactics": rec["tactics"], "evidence": refs[tid],
            "weight": round(w, 3), "url": rec["url"],
        })
    rows.sort(key=lambda r: -r["weight"])
    rows = rows[:max_items]
    rows.sort(key=lambda r: (AttackKB.tactic_rank(r["tactics"]), -r["weight"]))
    return rows


# --------------------------------------------------------------------------------------------------
# Tool 3: build_defensive_checklist
# --------------------------------------------------------------------------------------------------

# Curated defensive guidance per technique (current ATT&CK v20 IDs). Each containment action that
# affects users, accounts, hosts or network paths is marked requires_approval=True (human-in-the-loop).
DEFENSE_PLAYBOOK: dict[str, dict] = {
    "T1486": {"monitor": ["Alert on bursts of file renames/modifications or new unknown extensions from one process or SMB session",
                          "Place canary files on file shares and alert on any modification",
                          "Alert on ransom-note-like files (README/RECOVER *.txt) written to many directories"],
              "contain": [("Network-isolate hosts showing mass-encryption behaviour using EDR host containment", True),
                          ("Disconnect affected subnets at the switch level and coordinate out-of-band (CISA checklist step 1-2)", True)]},
    "T1490": {"monitor": ["Alert on vssadmin delete shadows / resize shadowstorage, wmic shadowcopy delete, wbadmin delete catalog and bcdedit /set recoveryenabled no",
                          "Alert when the Volume Shadow Copy service is stopped or disabled"],
              "contain": [("Confirm offline/immutable backups are disconnected and protected before restoration", False)]},
    "T1489": {"monitor": ["Alert on bulk stops of backup, database and security services (net stop, sc config, taskkill) in a short window"],
              "contain": []},
    "T1485": {"monitor": ["Alert on mass deletion of files, logs or recycle-bin contents by a single process"], "contain": []},
    "T1529": {"monitor": ["Alert on unexpected hypervisor/VM shutdowns (esxcli vm process kill, vim-cmd) outside change windows"],
              "contain": [("Restrict ESXi/vCenter management to a privileged access workstation and disable ESXi SSH", True)]},
    "T1657": {"monitor": [],
              "contain": [("Escalate to leadership, legal, insurer and law enforcement before any contact with the actor (CISA does not recommend paying)", True)]},
    "T1566": {"monitor": ["Alert on Office/PDF readers spawning script interpreters; triage user-reported phishing quickly"],
              "contain": [("Purge the identified phishing messages from all mailboxes and block the sender/URLs", True)]},
    "T1190": {"monitor": ["Alert on unexpected child processes of web/VPN/RMM servers and new web shells; track KEV exposure of internet-facing assets"],
              "contain": [("Take the vulnerable internet-facing service offline or apply the emergency patch/mitigation", True)]},
    "T1133": {"monitor": ["Alert on VPN/RDP logons from new geographies, impossible travel or accounts without MFA"],
              "contain": [("Temporarily restrict VPN/remote access to MFA-enforced accounts and known IP ranges", True)]},
    "T1078": {"monitor": ["Baseline account behaviour; alert on dormant or service accounts logging on interactively"],
              "contain": [("Disable or force-reset suspected compromised accounts and revoke active sessions/tokens", True)]},
    "T1189": {"monitor": ["Alert on browsers spawning PowerShell/cmd or downloading executables named like browser/security updates"],
              "contain": [("Block the identified malicious or compromised domains at DNS filtering and proxy", True)]},
    "T1204.004": {"monitor": ["Alert on PowerShell with encoded commands launched from the Run dialog/explorer.exe (ClickFix); review RunMRU registry entries"],
                  "contain": [("Block identified fake-CAPTCHA/ClickFix domains at DNS and proxy", True)]},
    "T1059.001": {"monitor": ["Enable PowerShell Script Block (4104) and Module logging; alert on -EncodedCommand, hidden windows and download cradles"],
                  "contain": []},
    "T1047": {"monitor": ["Alert on remote WMI execution (wmiprvse.exe spawning cmd/powershell) across many hosts"], "contain": []},
    "T1569.002": {"monitor": ["Alert on PsExec-style remote service creation (event 7045, PSEXESVC)"],
                  "contain": [("Block SMB/admin-share access between workstations with host firewall rules", True)]},
    "T1072": {"monitor": ["Alert on PDQ/BigFix/SCCM jobs pushing unknown executables or created outside change windows"],
              "contain": [("Suspend software-deployment tool jobs pending review", True)]},
    "T1136": {"monitor": ["Alert on new domain/local accounts (event 4720) and privileged group additions (4728/4732/4756)"],
              "contain": [("Disable unauthorized accounts created during the intrusion", True)]},
    "T1068": {"monitor": ["Alert on exploitation patterns for ZeroLogon, PrintNightmare and NoPac; patch status of domain controllers"],
              "contain": []},
    "T1685": {"monitor": ["Alert on EDR/AV agent stop, uninstall or tamper events and Defender exclusion changes",
                          "Alert on loading of known vulnerable drivers (BYOVD) and enable the Microsoft vulnerable driver blocklist"],
              "contain": [("Isolate any host whose EDR agent stops reporting unexpectedly", True)]},
    "T1685.005": {"monitor": ["Alert on Security log cleared (event 1102), System log cleared (104) and wevtutil cl; forward logs to a central SIEM"],
                  "contain": []},
    "T1003": {"monitor": ["Alert on non-system processes accessing LSASS (Sysmon 10) and procdump/comsvcs.dll MiniDump usage"],
              "contain": [("Reset credentials of accounts used on affected hosts once eradication is complete", True)]},
    "T1003.003": {"monitor": ["Alert on ntdsutil 'ifm', shadow copies created on domain controllers and DRSUAPI replication from non-DC hosts"],
                  "contain": [("Plan a double KRBTGT reset and privileged credential rotation once the domain is clean", True)]},
    "T1021.001": {"monitor": ["Alert on RDP (logon type 10) between workstations and from servers to workstations"],
                  "contain": [("Block inbound RDP at host firewalls except from approved jump hosts", True)]},
    "T1219": {"monitor": ["Inventory and alert on unapproved RMM tools (AnyDesk, Splashtop, ScreenConnect, Atera, RustDesk) by hash, process and destination"],
              "contain": [("Block unapproved remote access software with application control and egress filtering", True)]},
    "T1484.001": {"monitor": ["Alert on GPO modifications (event 5136) and new scripts/scheduled tasks pushed via SYSVOL"],
                  "contain": [("Restrict GPO edit rights and revert malicious Group Policy changes", True)]},
    "T1560": {"monitor": ["Alert on WinRAR/7-Zip creating large or split archives on servers and file shares"], "contain": []},
    "T1048": {"monitor": ["Alert on WinSCP/FileZilla/SFTP sessions to unknown external hosts and large outbound transfers"],
              "contain": [("Block egress to the identified exfiltration destinations", True)]},
    "T1567": {"monitor": ["Alert on rclone, MEGAsync or AzCopy execution and large uploads to unsanctioned cloud storage"],
              "contain": [("Block identified cloud-storage exfiltration endpoints at proxy/firewall", True)]},
}

BASELINE_RESPONSE = [
    ("Contain & Respond", "Follow the CISA Ransomware Response Checklist: isolate impacted systems, triage critical assets, preserve evidence (memory, logs) before reimaging", False, "CISA Ransomware Response Checklist"),
    ("Contain & Respond", "Notify incident response lead, leadership and cyber insurer; consider reporting to CISA / FBI IC3", True, "CISA Ransomware Response Checklist"),
]


def _playbook_entry(tid: str) -> dict | None:
    for key in (tid, tid.split(".")[0]):
        if key in DEFENSE_PLAYBOOK:
            return DEFENSE_PLAYBOOK[key]
    return None


def build_defensive_checklist(technique_ids: list[str], include_response: bool = True,
                              kb: AttackKB | None = None, max_mitigations: int = 3) -> dict:
    """Convert techniques into a monitoring / hardening / containment checklist.
    Containment steps that affect accounts, hosts or network paths require human approval."""
    kb = kb or get_kb()
    items: list[dict] = []
    seen_mit: dict[str, dict] = {}
    unknown = []
    for raw in technique_ids:
        tid = kb.normalize_id(raw)
        if not tid:
            unknown.append(raw)
            continue
        rec = kb.techniques[tid]
        label = f"{tid} {rec['name']}"
        entry = _playbook_entry(tid)
        if entry:
            for m in entry["monitor"]:
                items.append({"phase": "Detect & Monitor", "technique": label, "action": m,
                              "source": "Group 3B detection playbook", "requires_approval": False})
        for d in rec["detections"][:1]:
            items.append({"phase": "Detect & Monitor", "technique": label,
                          "action": f"Implement ATT&CK detection strategy {d['id']}: {d['name']}",
                          "source": f"MITRE ATT&CK {d['id']}", "requires_approval": False})
        for m in rec["mitigations"][:max_mitigations]:
            if m["id"] in seen_mit:
                seen_mit[m["id"]]["technique"] += f", {tid}"
                continue
            how = re.split(r"(?<=\.)\s", m["how"])[0] if m["how"] else ""
            item = {"phase": "Prevent & Harden", "technique": label,
                    "action": f"{m['id']} {m['name']}" + (f" — {how}" if how else ""),
                    "source": f"MITRE ATT&CK {m['id']}", "requires_approval": False}
            seen_mit[m["id"]] = item
            items.append(item)
        if entry:
            for action, needs_ok in entry["contain"]:
                items.append({"phase": "Contain & Respond", "technique": label, "action": action,
                              "source": "CISA #StopRansomware guidance / Group 3B playbook",
                              "requires_approval": needs_ok})
    if include_response and technique_ids:
        for phase, action, needs_ok, src in BASELINE_RESPONSE:
            items.append({"phase": phase, "technique": "All", "action": action, "source": src,
                          "requires_approval": needs_ok})
    # de-duplicate identical actions (e.g. T1566 and T1566.004 share playbook entries)
    merged: dict[tuple, dict] = {}
    for it in items:
        key = (it["phase"], it["action"])
        if key in merged:
            tid = it["technique"].split(" ")[0]
            if tid not in merged[key]["technique"]:
                merged[key]["technique"] += f", {tid}"
        else:
            merged[key] = it
    items = list(merged.values())
    order = {"Detect & Monitor": 0, "Prevent & Harden": 1, "Contain & Respond": 2}
    items.sort(key=lambda it: order[it["phase"]])
    for i, it in enumerate(items, start=1):
        it["id"] = f"C{i:02d}"
        it["status"] = "PENDING APPROVAL" if it["requires_approval"] else "recommended"
    return {
        "items": items,
        "n_pending_approval": sum(it["requires_approval"] for it in items),
        "unknown_techniques": unknown,
    }


# --------------------------------------------------------------------------------------------------
# Tool 4: summarize_report
# --------------------------------------------------------------------------------------------------

SUMMARY_SECTIONS = [
    ("Who", ("overview",)),
    ("How they get in", ("initial access",)),
    ("What they do", ("execution", "credential", "discovery", "lateral", "defense", "persistence", "privilege", "command")),
    ("Impact & extortion", ("impact", "exfiltration", "extortion")),
    ("Priority defensive actions", ("mitigation",)),
]


def _sentences(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = re.sub(r"^\s*(?:[-*]|\d+\.)\s*", "", line).strip()
        if line:
            out += [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", line) if len(s.strip()) > 30]
    return out


def report_chunks(doc_id: str, index: VectorIndex | None = None) -> list[Hit]:
    index = index or get_index()
    rows = [c for c in index.chunks if c["doc_id"] == doc_id]
    return [Hit(c, 1.0, 1.0, 1.0, i, f"S{i}") for i, c in enumerate(rows, start=1)]


def summarize_report(doc_id: str, llm=None, index: VectorIndex | None = None, kb: AttackKB | None = None) -> dict:
    """Executive summary of one report: LLM-generated when available, otherwise extractive."""
    hits = report_chunks(doc_id, index)
    if not hits:
        return {"error": f"Unknown report {doc_id}"}
    meta = hits[0].chunk
    techniques = map_attack_techniques(hits, kb, max_items=40)
    mode = "extractive"
    summary_md = ""
    if llm is not None and llm.available():
        context = "\n\n".join(f"[{h.ref}] ({h.chunk['section']}) {sanitize_context(h.chunk['text'])}" for h in hits)
        prompt = [
            {"role": "system", "content": "You are a senior cyber threat intelligence analyst writing for executives. "
             "Use ONLY the provided report excerpts. Cite every claim with [S#] tags. Defensive framing only."},
            {"role": "user", "content": f"Report: {meta['title']}\n\nExcerpts:\n{context}\n\n"
             "Write an executive summary in markdown with these headings: **Bottom line** (2 sentences), "
             "**Who and how they get in**, **What they do once inside**, **Business impact**, "
             "**Top 5 actions for this week** (numbered). Max 250 words. Cite with [S#]."},
        ]
        try:
            summary_md = llm.chat(prompt)
            mode = f"llm ({llm.name})"
        except Exception:
            summary_md = ""
    if not summary_md:
        parts = []
        for heading, keys in SUMMARY_SECTIONS:
            matched = [h for h in hits if any(k in h.chunk["section"].lower() for k in keys)]
            if not matched:
                continue
            n = 5 if heading.startswith("Priority") else 2
            sents = []
            for h in matched:
                for s in _sentences(h.chunk["text"])[: n - len(sents)]:
                    sents.append(f"{s} [{h.ref}]")
                if len(sents) >= n:
                    break
            if heading.startswith("Priority"):
                parts.append(f"**{heading}**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(sents, 1)))
            else:
                parts.append(f"**{heading}.** " + " ".join(sents))
        summary_md = "\n\n".join(parts)
    return {
        "doc_id": doc_id, "title": meta["title"], "url": meta["url"], "advisory_id": meta["advisory_id"],
        "published": meta["published"], "actor": meta["actor"], "mode": mode, "summary": summary_md,
        "techniques": techniques, "sources": [h.to_dict() for h in hits],
    }


TOOL_SPECS = [
    {"name": "search_ransomware_intel",
     "description": "Search CISA #StopRansomware advisories, MITRE ATT&CK and response playbooks. "
                    "Args: query (str), actor (optional), sector (optional), source_type (optional: cisa_advisory, "
                    "mitre_technique, mitre_software, playbook)."},
    {"name": "map_attack_techniques",
     "description": "List the MITRE ATT&CK techniques evidenced in the retrieved passages, in kill-chain order."},
    {"name": "build_defensive_checklist",
     "description": "Turn techniques into monitoring, hardening and containment steps. Containment needs analyst approval."},
    {"name": "summarize_report",
     "description": "Executive summary of a single report. Args: doc_id."},
]
