"""LLM clients: Ollama (default, free/local), any OpenAI-compatible endpoint (LM Studio, vLLM, hosted
APIs), or none. With no LLM available the agent still works in deterministic extractive mode."""
from __future__ import annotations

import json
import logging
import re

import requests

from . import config

log = logging.getLogger(__name__)


class LLMError(RuntimeError):
    pass


class BaseLLM:
    name = "none"

    def available(self) -> bool:
        return False

    def chat(self, messages: list[dict], json_mode: bool = False, temperature: float = 0.1) -> str:
        raise LLMError("No LLM configured")

    def chat_json(self, messages: list[dict]) -> dict:
        raw = self.chat(messages, json_mode=True)
        return parse_json(raw)


class NullLLM(BaseLLM):
    pass


class OllamaLLM(BaseLLM):
    def __init__(self, model: str = config.OLLAMA_MODEL, host: str = config.OLLAMA_HOST):
        self.model, self.host = model, host.rstrip("/")
        self.name = f"ollama:{model}"

    def available(self) -> bool:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=1.5)
            names = [m.get("name", "") for m in r.json().get("models", [])]
            return r.ok and any(n == self.model or n.split(":")[0] == self.model.split(":")[0] for n in names)
        except Exception:
            return False

    def chat(self, messages, json_mode=False, temperature=0.1):
        payload = {"model": self.model, "messages": messages, "stream": False,
                   "options": {"temperature": temperature, "num_ctx": 8192}}
        if json_mode:
            payload["format"] = "json"
        try:
            r = requests.post(f"{self.host}/api/chat", json=payload, timeout=config.LLM_TIMEOUT)
            r.raise_for_status()
            return r.json()["message"]["content"]
        except Exception as exc:
            raise LLMError(f"Ollama call failed: {exc}") from exc


class OpenAICompatLLM(BaseLLM):
    def __init__(self, base_url: str = config.OPENAI_BASE_URL, api_key: str = config.OPENAI_API_KEY,
                 model: str = config.OPENAI_MODEL):
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.api_key, self.model = api_key, model
        self.name = f"openai-compatible:{model}"

    def available(self) -> bool:
        return bool(self.api_key or config.OPENAI_BASE_URL)

    def chat(self, messages, json_mode=False, temperature=0.1):
        payload = {"model": self.model, "messages": messages, "temperature": temperature}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key or 'not-needed'}"}
        try:
            r = requests.post(f"{self.base_url}/chat/completions", json=payload, headers=headers,
                              timeout=config.LLM_TIMEOUT)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LLMError(f"OpenAI-compatible call failed: {exc}") from exc


def parse_json(raw: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", raw or "", re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    raise LLMError("LLM did not return valid JSON")


def get_llm(provider: str | None = None) -> BaseLLM:
    provider = (provider or config.LLM_PROVIDER).lower()
    if provider == "none":
        return NullLLM()
    if provider in ("auto", "ollama"):
        llm = OllamaLLM()
        if llm.available():
            return llm
        if provider == "ollama":
            log.warning("Ollama model %s not reachable at %s", config.OLLAMA_MODEL, config.OLLAMA_HOST)
            return NullLLM()
    if provider in ("auto", "openai"):
        llm = OpenAICompatLLM()
        if llm.available():
            return llm
    return NullLLM()
