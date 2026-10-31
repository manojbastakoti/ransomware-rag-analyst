# Team roles and module ownership (Group 3B)

Replace the placeholders with your team's names. Every member contributed code, integration and testing, and can explain the full system.

| Student | Role (from the brief) | Owns | Key files |
|---|---|---|---|
| Student 1 — _name_ | **Data Lead** | Source selection, advisory write-ups, ATT&CK extraction, legacy-ID mapping, data card | `data/raw/`, `scripts/fetch_attack.py`, `src/ransomrag/ingest.py`, `docs/data_card.md` |
| Student 2 — _name_ | **RAG Lead** | Embeddings, hybrid dense + BM25 retrieval, metadata filters, actor/section boosts, retrieval baselines | `src/ransomrag/embeddings.py`, `src/ransomrag/vectorstore.py`, `scripts/build_index.py` |
| Student 3 — _name_ | **Agent Lead** | Planner (LLM + rules), tool definitions, technique-to-checklist workflow, grounding and approval checkpoint | `src/ransomrag/agent.py`, `src/ransomrag/tools.py`, `src/ransomrag/llm.py`, `src/ransomrag/approval.py` |
| Student 4 — _name_ | **App Lead** | Gradio UI (search, summarizer, approval, monitoring), Docker, screenshots, README | `src/ransomrag/ui.py`, `app.py`, `Dockerfile`, `docs/screenshots/` |
| Student 5 — _name_ | **Evaluation Lead** | 25 evaluation questions, safety cases, metrics, error analysis, guardrails, report and demo | `eval/`, `scripts/run_eval.py`, `tests/`, `src/ransomrag/guardrails.py`, `docs/report.md`, `docs/demo_script.md` |
