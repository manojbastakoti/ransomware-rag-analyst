"""Gradio web app: analyst Q&A, report summarizer, defensive checklist with human approval,
evaluation results and monitoring."""
from __future__ import annotations

import json
import re
import time

import gradio as gr

from . import tools
from .agent import RansomwareAnalystAgent
from .approval import ApprovalError, apply_decisions, checklist_to_markdown
from .config import EVAL_DIR, LOG_DIR
from .ingest import load_documents
from .monitoring import read_events, summarize_events

EXAMPLES = [
    "How does Akira ransomware usually get initial access?",
    "Which ransomware groups have targeted healthcare and how?",
    "How do we detect and contain Black Basta?",
    "We were hit by ransomware and servers are encrypted. What should we do first?",
    "What tools do ransomware actors use to exfiltrate data before encryption?",
    "How can we detect attempts to delete volume shadow copies?",
    "Summarize the Medusa advisory",
]

TECH_HEADERS = ["ID", "Technique", "Tactics", "Evidence"]
CHECK_HEADERS = ["ID", "Phase", "Status", "Action", "Technique", "Source"]


def _tech_rows(techs: list[dict]) -> list[list]:
    return [[t["id"], t["name"], ", ".join(t["tactics"]), ", ".join(t["evidence"])] for t in techs] or [["", "", "", ""]]


def _check_rows(cl: dict | None) -> list[list]:
    if not cl:
        return [["", "", "", "", "", ""]]
    return [[i["id"], i["phase"], i["status"], i["action"], i["technique"], i["source"]] for i in cl["items"]]


def _pending_choices(cl: dict | None) -> list[str]:
    if not cl:
        return []
    return [f"{i['id']} | {i['action']}" for i in cl["items"] if i["status"] == "PENDING APPROVAL"]


def _sources_md(sources: list[dict]) -> str:
    if not sources:
        return "_No sources retrieved._"
    out = []
    for s in sources:
        snippet = re.sub(r"\s+", " ", s["text"])[:280]
        link = f" · [open source]({s['url']})" if s.get("url") else ""
        out.append(f"**[{s['ref']}]** {s['title']} — *{s['section']}* "
                   f"(`{s['source_type']}`, score {s['score']:.2f}){link}\n> {snippet}…")
    return "\n\n".join(out)


def _trace_md(res: dict) -> str:
    plan = res.get("plan") or {}
    lines = [f"**Planner:** {plan.get('planner', '-')} · **intent:** {plan.get('intent', '-')} · "
             f"**tools selected:** {', '.join(plan.get('tools', [])) or '-'}", "",
             "| # | Tool | Arguments | Result | ms | OK |", "|---|---|---|---|---|---|"]
    for t in res.get("trace", []):
        args = json.dumps(t["args"])[:120].replace("|", "/")
        summ = (t["summary"] or "")[:160].replace("|", "/")
        lines.append(f"| {t['step']} | `{t['tool']}` | {args} | {summ} | {t['ms']} | {'✅' if t['ok'] else '❌'} |")
    cc = res.get("citation_check") or {}
    if cc:
        lines += ["", f"**Citation check:** {cc.get('n_valid', 0)}/{cc.get('n_citations', 0)} citations valid; "
                  f"invalid removed: {cc.get('invalid_refs') or 'none'}"]
    lines.append(f"\n**Latency:** {res.get('latency_ms')} ms · request `{res.get('request_id')}`")
    return "\n".join(lines)


def build_ui(agent: RansomwareAnalystAgent | None = None) -> gr.Blocks:
    agent = agent or RansomwareAnalystAgent()
    docs = load_documents()
    report_choices = [(f"{d['advisory_id']} — {d['title']}", d["doc_id"]) for d in docs
                      if d["source_type"] in ("cisa_advisory", "playbook")]
    actors = [""] + agent.index.actors()
    sectors = [""] + agent.index.sectors()
    llm_status = (f"🟢 LLM: `{agent.llm.name}`" if agent.llm.available()
                  else "🟡 No LLM reachable — running in **extractive mode** (start Ollama for generated answers)")

    # ------------------------------------------------------------------ callbacks
    def ask(query, actor, sector, source_type):
        res = agent.run(query, {"actor": actor or None, "sector": sector or None,
                                "source_type": source_type or None}).to_dict()
        badge = "⛔ Refused (out of scope)" if res["refused"] else f"Mode: `{res['mode']}`"
        warn = "".join(f"\n\n> ⚠️ {w}" for w in res["warnings"])
        answer = f"{badge}{warn}\n\n{res['answer']}"
        cl = res.get("checklist")
        summary_md = res["summary"]["summary"] if res.get("summary") else ""
        return (answer, _tech_rows(res["techniques"]), _sources_md(res["sources"]), _trace_md(res),
                _check_rows(cl), gr.update(choices=_pending_choices(cl), value=[]), cl, summary_md,
                "Checklist generated from your last question." if cl else
                "No checklist for this question — ask a *detect / contain / respond* question or enter technique IDs below.")

    def manual_checklist(tids_text):
        tids = [t for t in re.split(r"[,\s]+", tids_text or "") if t]
        if not tids:
            return _check_rows(None), gr.update(choices=[], value=[]), None, "Enter technique IDs such as `T1486, T1490`."
        cl = tools.build_defensive_checklist(tids, kb=agent.kb)
        msg = f"Built {len(cl['items'])} items; {cl['n_pending_approval']} need approval."
        if cl["unknown_techniques"]:
            msg += f" Unknown IDs ignored: {', '.join(cl['unknown_techniques'])}"
        return _check_rows(cl), gr.update(choices=_pending_choices(cl), value=[]), cl, msg

    def decide(cl, selected, analyst, justification, decision):
        if not cl:
            return _check_rows(None), gr.update(), cl, "No checklist loaded.", None
        ids = [s.split(" | ")[0] for s in (selected or [])]
        if not ids:
            return _check_rows(cl), gr.update(), cl, "Select at least one pending action.", None
        try:
            new = apply_decisions(cl, ids if decision == "approve" else [], analyst, justification,
                                  rejected_ids=ids if decision == "reject" else [])
        except ApprovalError as exc:
            return _check_rows(cl), gr.update(), cl, f"❌ {exc}", None
        export = LOG_DIR / "exports"
        export.mkdir(parents=True, exist_ok=True)
        path = export / f"checklist_{time.strftime('%Y%m%d_%H%M%S')}.md"
        path.write_text(checklist_to_markdown(new), encoding="utf-8")
        msg = (f"✅ {len(ids)} action(s) {decision}d by {analyst.strip()}. "
               f"{new['n_pending_approval']} still pending. Decision logged to logs/approvals.jsonl.")
        return _check_rows(new), gr.update(choices=_pending_choices(new), value=[]), new, msg, str(path)

    def export_checklist(cl):
        if not cl:
            return None
        export = LOG_DIR / "exports"
        export.mkdir(parents=True, exist_ok=True)
        path = export / f"checklist_{time.strftime('%Y%m%d_%H%M%S')}.md"
        path.write_text(checklist_to_markdown(cl), encoding="utf-8")
        return str(path)

    def summarize(doc_id):
        if not doc_id:
            return "Choose a report.", _tech_rows([]), ""
        out = tools.summarize_report(doc_id, llm=agent.llm, index=agent.index, kb=agent.kb)
        head = (f"### {out['title']}\n{out['advisory_id']} · published {out['published']} · "
                f"[original]({out['url']}) · mode: `{out['mode']}`\n\n")
        return head + out["summary"], _tech_rows(out["techniques"]), _sources_md(out["sources"])

    def load_eval():
        p = EVAL_DIR / "results" / "report.md"
        return p.read_text(encoding="utf-8") if p.exists() else "_Run `python scripts/run_eval.py` to generate results._"

    def monitoring():
        ev = [e for e in read_events(limit=50) if e.get("type") == "agent_run"][-15:]
        rows = [[e["ts"], e.get("mode"), e.get("latency_ms"), ", ".join(e.get("tools", [])), e.get("n_sources"),
                 e.get("citations_valid"), e.get("refused")] for e in reversed(ev)] or [["", "", "", "", "", "", ""]]
        return summarize_events(), rows

    # ------------------------------------------------------------------ layout
    with gr.Blocks(title="Ransomware Threat Intelligence RAG Analyst") as demo:
        gr.Markdown(
            "# 🛡️ Ransomware Threat Intelligence RAG Analyst\n"
            "**Group 3B · AI/ML in Cybersecurity capstone · defensive use only.** Answers ransomware questions from "
            "CISA #StopRansomware advisories, MITRE ATT&CK and the CISA response checklist — with citations, "
            f"ATT&CK mapping and an approval-gated defensive checklist.\n\n{llm_status} · embeddings: "
            f"`{agent.index.embedder.name}` · {len(docs)} documents / {len(agent.index.chunks)} chunks")
        cl_state = gr.State(None)

        with gr.Tab("1 · Ask the analyst"):
            with gr.Row():
                with gr.Column(scale=3):
                    q = gr.Textbox(label="Question", lines=2, placeholder="e.g. How does Akira get initial access?")
                with gr.Column(scale=2):
                    with gr.Row():
                        f_actor = gr.Dropdown(actors, value="", label="Actor filter")
                        f_sector = gr.Dropdown(sectors, value="", label="Sector filter")
                    f_type = gr.Dropdown(["", "cisa_advisory", "mitre_technique", "mitre_software", "playbook"],
                                         value="", label="Source type filter")
            ask_btn = gr.Button("Ask", variant="primary")
            gr.Examples(EXAMPLES, inputs=q)
            answer = gr.Markdown()
            with gr.Row():
                with gr.Column():
                    gr.Markdown("#### Likely MITRE ATT&CK techniques (kill-chain order)")
                    tech_df = gr.Dataframe(headers=TECH_HEADERS, value=_tech_rows([]), wrap=True, interactive=False)
                with gr.Column():
                    gr.Markdown("#### Evidence / citations")
                    sources = gr.Markdown()
            with gr.Accordion("Agent trace (tool selection, results, latency, citation check)", open=False):
                trace = gr.Markdown()
            with gr.Accordion("Report summary (when requested)", open=False):
                ask_summary = gr.Markdown()

        with gr.Tab("2 · Defensive checklist & approval"):
            gr.Markdown("Checklist items come from the last question (or technique IDs below). **Containment actions "
                        "that affect accounts, hosts or network paths stay `PENDING APPROVAL` until a named analyst "
                        "approves them with a justification.** Every decision is logged.")
            cl_msg = gr.Markdown()
            with gr.Row():
                tids = gr.Textbox(label="Or build from technique IDs", placeholder="T1486, T1490, T1219, T1567.002")
                build_btn = gr.Button("Build checklist")
            check_df = gr.Dataframe(headers=CHECK_HEADERS, value=_check_rows(None), wrap=True, interactive=False)
            gr.Markdown("#### Human-in-the-loop approval")
            pending = gr.CheckboxGroup(choices=[], label="Pending containment actions")
            with gr.Row():
                analyst = gr.Textbox(label="Analyst name")
                justification = gr.Textbox(label="Justification", placeholder="e.g. Confirmed encryption on FS01; IR lead approved isolation")
            with gr.Row():
                approve_btn = gr.Button("✅ Approve selected", variant="primary")
                reject_btn = gr.Button("❌ Reject selected")
                export_btn = gr.Button("⬇️ Export checklist (Markdown)")
            approval_msg = gr.Markdown()
            export_file = gr.File(label="Checklist export")

        with gr.Tab("3 · Report summarizer"):
            rep = gr.Dropdown(report_choices, label="Report")
            sum_btn = gr.Button("Generate executive summary", variant="primary")
            rep_out = gr.Markdown()
            rep_tech = gr.Dataframe(headers=TECH_HEADERS, value=_tech_rows([]), wrap=True, interactive=False)
            with gr.Accordion("Sections used", open=False):
                rep_src = gr.Markdown()

        with gr.Tab("4 · Evaluation"):
            eval_btn = gr.Button("Reload evaluation report")
            eval_md = gr.Markdown(load_eval())

        with gr.Tab("5 · Monitoring"):
            mon_btn = gr.Button("Refresh")
            mon_json = gr.JSON()
            mon_df = gr.Dataframe(headers=["Time", "Mode", "Latency ms", "Tools", "Sources", "Valid citations", "Refused"],
                                  interactive=False)

        with gr.Tab("About & safety"):
            gr.Markdown((EVAL_DIR.parent / "docs" / "safety.md").read_text(encoding="utf-8")
                        if (EVAL_DIR.parent / "docs" / "safety.md").exists() else "")

        outs = [answer, tech_df, sources, trace, check_df, pending, cl_state, ask_summary, cl_msg]
        ask_btn.click(ask, [q, f_actor, f_sector, f_type], outs)
        q.submit(ask, [q, f_actor, f_sector, f_type], outs)
        build_btn.click(manual_checklist, [tids], [check_df, pending, cl_state, cl_msg])
        approve_btn.click(lambda c, s, a, j: decide(c, s, a, j, "approve"), [cl_state, pending, analyst, justification],
                          [check_df, pending, cl_state, approval_msg, export_file])
        reject_btn.click(lambda c, s, a, j: decide(c, s, a, j, "reject"), [cl_state, pending, analyst, justification],
                         [check_df, pending, cl_state, approval_msg, export_file])
        export_btn.click(export_checklist, [cl_state], [export_file])
        sum_btn.click(summarize, [rep], [rep_out, rep_tech, rep_src])
        eval_btn.click(load_eval, [], [eval_md])
        mon_btn.click(monitoring, [], [mon_json, mon_df])
    return demo
