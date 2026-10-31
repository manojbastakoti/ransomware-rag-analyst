"""Central configuration. Every setting can be overridden with an environment variable."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(os.getenv("RANSOMRAG_ROOT", Path(__file__).resolve().parents[2]))
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
ATTACK_SUBSET_PATH = DATA_DIR / "attack" / "attack_subset.json"
CHUNKS_PATH = DATA_DIR / "processed" / "chunks.jsonl"
DOCS_PATH = DATA_DIR / "processed" / "documents.json"
INDEX_DIR = DATA_DIR / "index"
LOG_DIR = Path(os.getenv("RANSOMRAG_LOG_DIR", ROOT / "logs"))
EVAL_DIR = ROOT / "eval"

# Retrieval
EMBEDDING_BACKEND = os.getenv("EMBEDDING_BACKEND", "auto")  # auto | sentence-transformers | tfidf
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
HYBRID_ALPHA = float(os.getenv("HYBRID_ALPHA", "0.55"))  # weight on dense score vs BM25
TOP_K = int(os.getenv("TOP_K", "6"))
MIN_RELEVANCE = float(os.getenv("MIN_RELEVANCE", "0.15"))

# LLM
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto")  # auto | ollama | openai | none
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "")  # e.g. http://localhost:1234/v1 for LM Studio
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "90"))

MAX_QUERY_CHARS = 1000
