"""Basic monitoring: structured JSONL event log of requests, tool calls, latency and errors.
Questions are stored as a SHA-256 hash + length only, so the log never holds analyst input verbatim."""
from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path

from .config import LOG_DIR

EVENTS = "events.jsonl"


def _path(name: str) -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / name


def query_fingerprint(query: str) -> dict:
    return {"query_sha256": hashlib.sha256(query.encode()).hexdigest()[:16], "query_len": len(query)}


def log_event(event: dict, name: str = EVENTS) -> None:
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **event}
    try:
        with _path(name).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
    except OSError:
        pass  # monitoring must never break the app


def read_events(name: str = EVENTS, limit: int = 500) -> list[dict]:
    p = _path(name)
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(x) for x in lines if x.strip()]


def summarize_events(limit: int = 500) -> dict:
    ev = [e for e in read_events(limit=limit) if e.get("type") == "agent_run"]
    if not ev:
        return {"requests": 0}
    lat = sorted(e.get("latency_ms", 0) for e in ev)
    tools = Counter(t for e in ev for t in e.get("tools", []))
    return {
        "requests": len(ev),
        "refused": sum(e.get("refused", False) for e in ev),
        "tool_errors": sum(e.get("tool_errors", 0) for e in ev),
        "ungrounded_llm_fallbacks": sum(e.get("grounding_fallback", False) for e in ev),
        "median_latency_ms": lat[len(lat) // 2],
        "p95_latency_ms": lat[min(len(lat) - 1, int(len(lat) * 0.95))],
        "modes": dict(Counter(e.get("mode", "?") for e in ev)),
        "tool_usage": dict(tools),
    }
