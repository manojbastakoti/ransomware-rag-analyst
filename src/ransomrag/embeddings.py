"""Embedding backends.

* ``sentence-transformers`` (default when installed): BAAI/bge-small-en-v1.5, a free local model.
* ``tfidf``: TF-IDF + truncated SVD (latent semantic analysis). Fully offline, no model download.
  Used automatically when sentence-transformers is not installed or the model cannot be fetched.
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path

import numpy as np

from .config import EMBEDDING_BACKEND, EMBEDDING_MODEL

log = logging.getLogger(__name__)


def _normalize(x: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return (x / norms).astype(np.float32)


class TfidfLsaEmbedder:
    name = "tfidf-lsa"

    def __init__(self, n_components: int = 192):
        self.n_components = n_components
        self.vectorizer = None
        self.svd = None

    def fit(self, texts: list[str]) -> "TfidfLsaEmbedder":
        from sklearn.decomposition import TruncatedSVD
        from sklearn.feature_extraction.text import TfidfVectorizer

        from .vectorstore import tokenize

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2), sublinear_tf=True, min_df=1, tokenizer=tokenize, lowercase=False,
            token_pattern=None,
        )
        tfidf = self.vectorizer.fit_transform(texts)
        k = max(2, min(self.n_components, tfidf.shape[0] - 1, tfidf.shape[1] - 1))
        self.svd = TruncatedSVD(n_components=k, random_state=42).fit(tfidf)
        return self

    def encode(self, texts: list[str], is_query: bool = False) -> np.ndarray:
        return _normalize(self.svd.transform(self.vectorizer.transform(texts)))

    def save(self, path: Path) -> None:
        with open(path, "wb") as fh:
            pickle.dump({"vectorizer": self.vectorizer, "svd": self.svd, "n": self.n_components}, fh)

    @classmethod
    def load(cls, path: Path) -> "TfidfLsaEmbedder":
        with open(path, "rb") as fh:
            d = pickle.load(fh)
        e = cls(d["n"])
        e.vectorizer, e.svd = d["vectorizer"], d["svd"]
        return e


class SentenceTransformerEmbedder:
    QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name
        self.name = f"st:{model_name}"
        self.model = SentenceTransformer(model_name)

    def fit(self, texts: list[str]) -> "SentenceTransformerEmbedder":
        return self

    def encode(self, texts: list[str], is_query: bool = False) -> np.ndarray:
        if is_query and "bge" in self.model_name.lower():
            texts = [self.QUERY_PREFIX + t for t in texts]
        vecs = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return np.asarray(vecs, dtype=np.float32)

    def save(self, path: Path) -> None:
        Path(path).write_text(self.model_name, encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "SentenceTransformerEmbedder":
        return cls(Path(path).read_text(encoding="utf-8").strip())


def make_embedder(backend: str = EMBEDDING_BACKEND):
    if backend in ("auto", "sentence-transformers"):
        try:
            return SentenceTransformerEmbedder()
        except Exception as exc:  # ImportError, or no network to download the model
            if backend == "sentence-transformers":
                raise
            log.warning("sentence-transformers unavailable (%s); falling back to TF-IDF/LSA embeddings", exc)
    return TfidfLsaEmbedder()
