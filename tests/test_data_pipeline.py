from ransomrag.ingest import build_corpus, parse_front_matter, split_sections


def test_front_matter_parsing():
    meta, body = parse_front_matter("---\ndoc_id: x\nsectors: healthcare; education\n---\n# T\n## A\ntext")
    assert meta["doc_id"] == "x" and "## A" in body


def test_sections_split():
    secs = split_sections("# Title\n> note\n## Overview\nhello\n## Impact\nworld")
    assert [s for s, _ in secs] == ["Overview", "Impact"]


def test_corpus_scope_and_metadata():
    docs, chunks = build_corpus()
    assert 20 <= len(docs) <= 50, "brief asks for 20-50 curated documents"
    types = {d["source_type"] for d in docs}
    assert {"cisa_advisory", "mitre_technique", "mitre_software", "playbook"} <= types
    for c in chunks:
        assert c.chunk_id and c.text and c.url.startswith("https://")
    akira = [c for c in chunks if c.doc_id == "cisa-aa24-109a-akira"]
    assert any("T1190" in c.techniques for c in akira)
    assert all(c.actor == "Akira" for c in akira)


def test_legacy_attack_ids_are_normalised(kb):
    # 2023 advisories cite T1562.001; ATT&CK v19+ moved it to T1685
    assert kb.normalize_id("T1562.001") == "T1685"
    assert kb.normalize_id("T1486") == "T1486"
    assert kb.normalize_id("T9999") is None
