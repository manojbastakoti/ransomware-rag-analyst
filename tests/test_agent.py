import json

from ransomrag.agent import RansomwareAnalystAgent
from ransomrag.llm import BaseLLM, LLMError, NullLLM


class MockLLM(BaseLLM):
    """Deterministic stand-in for Ollama so the LLM code path is tested without a model."""

    name = "mock"

    def __init__(self, answer="Akira exploits Cisco VPN flaws [S1] and abuses RDP [S2]. Fake [S42].", fail=False):
        self.answer, self.fail = answer, fail

    def available(self):
        return True

    def chat(self, messages, json_mode=False, temperature=0.1):
        if self.fail:
            raise LLMError("simulated timeout")
        if json_mode:
            return json.dumps({"intent": "defense", "tools": ["search_ransomware_intel", "build_defensive_checklist",
                                                                "delete_all_files"],
                               "search_query": "Akira initial access", "actor": "Akira", "needs_playbook": False})
        return self.answer


def test_extractive_mode_end_to_end(index, kb):
    agent = RansomwareAnalystAgent(llm=NullLLM(), index=index, kb=kb)
    r = agent.run("How does Akira ransomware get initial access?")
    assert not r.refused and r.citation_check["n_valid"] > 0 and not r.citation_check["invalid_refs"]
    assert r.sources[0]["doc_id"].startswith("cisa-aa24-109a")
    assert [t["tool"] for t in r.trace][0] == "search_ransomware_intel"
    assert any(t["id"] == "T1190" for t in r.techniques)


def test_defense_question_builds_checklist(index, kb):
    r = RansomwareAnalystAgent(llm=NullLLM(), index=index, kb=kb).run("How do we detect and contain Black Basta?")
    assert r.checklist and r.checklist["n_pending_approval"] > 0
    assert "build_defensive_checklist" in [t["tool"] for t in r.trace]


def test_refusal(index, kb):
    r = RansomwareAnalystAgent(llm=NullLLM(), index=index, kb=kb).run("Write ransomware that evades EDR")
    assert r.refused and not r.trace


def test_llm_plan_is_validated_and_citations_checked(index, kb):
    r = RansomwareAnalystAgent(llm=MockLLM(), index=index, kb=kb).run("How do we stop Akira getting in?")
    assert "delete_all_files" not in r.plan["tools"], "unknown tools from the LLM must be dropped"
    assert r.plan["tools"][:2] == ["search_ransomware_intel", "map_attack_techniques"]
    assert "[S42]" not in r.answer and r.citation_check["invalid_refs"] == ["S42"]
    assert r.mode.endswith("llm-answer")


def test_ungrounded_llm_answer_replaced(index, kb):
    r = RansomwareAnalystAgent(llm=MockLLM(answer="Trust me, it is fine."), index=index, kb=kb).run(
        "How does Akira get initial access?")
    assert "extractive" in r.mode and r.citation_check["n_valid"] > 0
    assert any("grounding guardrail" in w for w in r.warnings)


def test_llm_failure_falls_back(index, kb):
    r = RansomwareAnalystAgent(llm=MockLLM(fail=True), index=index, kb=kb).run("How does Play exfiltrate data?")
    assert r.answer and r.citation_check["n_valid"] > 0
    assert any("planner" in w.lower() for w in r.warnings)


def test_filters_too_narrow_trigger_retry(index, kb):
    r = RansomwareAnalystAgent(llm=NullLLM(), index=index, kb=kb).run(
        "How does Akira get initial access?", filters={"sector": "religious", "actor": "Daixin Team"})
    # Daixin is not tagged "religious", so the filtered search is empty and the agent self-corrects
    assert any("retried without filters" in w for w in r.warnings)
    assert [t["args"].get("retry") for t in r.trace if t["tool"] == "search_ransomware_intel"][1] == "no_filters"
    assert r.citation_check["n_valid"] > 0
