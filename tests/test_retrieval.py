def test_actor_question_hits_actor_advisory(index):
    hits = index.search("How does Akira ransomware get initial access?", k=3)
    assert hits[0].chunk["doc_id"] == "cisa-aa24-109a-akira"


def test_sector_filter(index):
    hits = index.search("ransomware encryption", k=10, filters={"sector": "healthcare"})
    assert hits and all("healthcare" in h.chunk["sectors"] for h in hits)


def test_actor_filter_includes_mitre_alias(index):
    hits = index.search("techniques", k=20, filters={"actor": "ALPHV Blackcat"})
    assert {h.chunk["source_type"] for h in hits} >= {"cisa_advisory"}
    assert all(h.chunk["actor"] in ("ALPHV Blackcat", "BlackCat") for h in hits)


def test_technique_filter(index):
    hits = index.search("shadow copies", k=10, filters={"technique": "T1490"})
    assert hits and all(any(t.startswith("T1490") for t in h.chunk["techniques"]) for h in hits)


def test_unknown_filter_returns_empty(index):
    assert index.search("anything", filters={"actor": "NoSuchGroup"}) == []
