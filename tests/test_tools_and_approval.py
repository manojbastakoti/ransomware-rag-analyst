import pytest

from ransomrag import tools
from ransomrag.approval import ApprovalError, apply_decisions, checklist_to_markdown


def test_technique_mapping_kill_chain_order(index, kb):
    hits = tools.search_ransomware_intel("Play ransomware initial access exfiltration impact", index=index, actor="Play")
    techs = tools.map_attack_techniques(hits, kb)
    ids = [t["id"] for t in techs]
    assert "T1486" in ids and "T1190" in ids
    assert ids.index("T1190") < ids.index("T1486")  # initial access before impact
    assert all(t["evidence"] for t in techs)


def test_checklist_requires_approval_for_containment(kb):
    cl = tools.build_defensive_checklist(["T1486", "T1490", "T1219", "T1562.001"], kb=kb)
    phases = {i["phase"] for i in cl["items"]}
    assert phases == {"Detect & Monitor", "Prevent & Harden", "Contain & Respond"}
    sensitive = [i for i in cl["items"] if i["requires_approval"]]
    assert sensitive and all(i["status"] == "PENDING APPROVAL" for i in sensitive)
    assert cl["n_pending_approval"] == len(sensitive)
    assert any("M1053" in i["action"] for i in cl["items"])  # Data Backup mitigation for T1490/T1486


def test_unknown_technique_reported(kb):
    cl = tools.build_defensive_checklist(["T9999"], kb=kb)
    assert cl["unknown_techniques"] == ["T9999"]


def test_approval_flow(kb):
    cl = tools.build_defensive_checklist(["T1486"], kb=kb)
    pending = [i["id"] for i in cl["items"] if i["requires_approval"]]
    with pytest.raises(ApprovalError):
        apply_decisions(cl, pending[:1], analyst="", justification="valid reason here")
    with pytest.raises(ApprovalError):
        apply_decisions(cl, pending[:1], analyst="Asha", justification="ok")
    out = apply_decisions(cl, pending[:1], analyst="Asha", justification="Confirmed encryption on FS01",
                          rejected_ids=pending[1:2])
    assert out["approved"] == pending[:1]
    assert out["n_pending_approval"] == len(pending) - len(pending[:2])
    assert cl["n_pending_approval"] == len(pending), "original checklist must not be mutated"
    md = checklist_to_markdown(out)
    assert "APPROVED by Asha" in md


def test_report_summary_extractive(index, kb):
    out = tools.summarize_report("cisa-aa25-071a-medusa", llm=None, index=index, kb=kb)
    assert out["mode"] == "extractive"
    assert "**Priority defensive actions**" in out["summary"]
    assert "[S" in out["summary"] and any(t["id"] == "T1486" for t in out["techniques"])
