## Scope, safety and ethics

**Defensive use only.** This prototype helps SOC and threat-intelligence analysts understand ransomware behaviour and plan detection, hardening and response. It is a decision-support tool, not an autonomous responder.

| Control | How it is implemented |
|---|---|
| Public data only | Corpus = public CISA #StopRansomware advisories (TLP:CLEAR), MITRE ATT&CK and CISA's public response checklist. No student, patient, employee or organisational data. No malware samples, no live IOCs fetched, no scanning. |
| Offensive-use refusal | `guardrails.check_query` refuses requests to build/deploy malware, evade EDR for deployment, write working exploits, draft ransom notes or launder ransom payments, and redirects to a defensive question. |
| Prompt-injection defence (OWASP LLM01) | Injection phrases in the question are neutralised and flagged; instruction-like lines in retrieved text are stripped before reaching the LLM (RAG-poisoning defence); source text is framed as data, not instructions. |
| Grounding / hallucination control (OWASP LLM09) | Every answer must cite retrieved sources as `[S#]`. Citations to sources that were not retrieved are removed; an LLM answer with no valid citation is rejected and replaced by a fully cited extractive answer. |
| Excessive agency (OWASP LLM06) | The agent can only call four read-only tools. Tool names proposed by the LLM are validated against an allow-list. The agent never executes containment actions. |
| Human-in-the-loop | Containment actions that affect accounts, hosts, network paths or external communication are created as `PENDING APPROVAL`. Only a named analyst with a written justification can approve or reject them; decisions are appended to `logs/approvals.jsonl`. |
| Privacy-preserving monitoring | `logs/events.jsonl` stores latency, tools used, errors and citation counts. Questions are stored only as a SHA-256 fingerprint and length. |
| Secrets | No API keys in code. LLM endpoints are configured with environment variables (`.env.example`). The default LLM is local (Ollama). |

**Limitations to keep in mind:** the advisories are analyst-curated summaries (always check the original link for full text and IOCs); intelligence ages quickly; technique mapping is evidence-based but not exhaustive; the tool does not replace an incident-response team, legal counsel or law-enforcement engagement. CISA, MS-ISAC and the FBI do not recommend paying ransoms.
