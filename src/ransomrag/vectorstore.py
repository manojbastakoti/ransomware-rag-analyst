"""Lightweight persistent vector store with metadata filters and hybrid (dense + BM25) scoring.

Exact cosine search over a NumPy matrix — equivalent to a FAISS ``IndexFlatIP`` and fast for the
~200 chunks in this corpus. Metadata filters: actor (incl. aliases), sector, technique, tactic,
source_type.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import snowballstemmer
from rank_bm25 import BM25Okapi

from .config import CHUNKS_PATH, HYBRID_ALPHA, INDEX_DIR
from .embeddings import SentenceTransformerEmbedder, TfidfLsaEmbedder, make_embedder
from .ingest import load_chunks

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\.\-]*")
STOP = set(
    "a an and are as at be by can do does for from has have how i in is it its of on or our should "
    "that the their them they this to us was we what when which who why will with you your".split()
)


_STEMMER = snowballstemmer.stemmer("english")
TID_TOKEN = re.compile(r"^t\d{4}(\.\d{3})?$")


def tokenize(text: str) -> list[str]:
    """Lower-case, drop stop words, stem (keeping ATT&CK IDs such as t1486 intact)."""
    toks = [t.strip(".-") for t in TOKEN_RE.findall(text.lower())]
    toks = [t for t in toks if t not in STOP and len(t) > 1]
    return [t if TID_TOKEN.match(t) else _STEMMER.stemWord(t) for t in toks]


@dataclass
class Hit:
    chunk: dict
    score: float
    dense: float
    sparse: float
    rank: int = 0
    ref: str = ""

    def to_dict(self) -> dict:
        c = self.chunk
        return {
            "ref": self.ref, "chunk_id": c["chunk_id"], "doc_id": c["doc_id"], "title": c["title"],
            "section": c["section"], "url": c["url"], "source_type": c["source_type"], "actor": c["actor"],
            "score": round(self.score, 4), "techniques": c["techniques"], "text": c["text"],
        }


class VectorIndex:
    def __init__(self, chunks: list[dict], embeddings: np.ndarray, embedder, mode: str = "hybrid"):
        self.chunks = chunks
        self.embeddings = embeddings
        self.embedder = embedder
        self.mode = mode
        self.bm25 = BM25Okapi([tokenize(self._index_text(c)) for c in chunks])
        self.actor_names = self._actor_lexicon()

    # ---------------------------------------------------------------- build / persist
    @staticmethod
    def _index_text(c: dict) -> str:
        names = " ".join([c["actor"], *c.get("aliases", [])]) if c["actor"] != "generic" else ""
        return f"{c['title']}. {c['section']}. {names}. {' '.join(c['techniques'])}. {c['text']}"

    @classmethod
    def build(cls, chunks: list[dict] | None = None, backend: str | None = None) -> "VectorIndex":
        chunks = chunks or load_chunks(CHUNKS_PATH)
        embedder = make_embedder(backend) if backend else make_embedder()
        texts = [cls._index_text(c) for c in chunks]
        embedder.fit(texts)
        return cls(chunks, embedder.encode(texts), embedder)

    def save(self, directory: Path = INDEX_DIR) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        np.save(directory / "embeddings.npy", self.embeddings)
        (directory / "chunks.json").write_text(json.dumps(self.chunks), encoding="utf-8")
        kind = "tfidf" if isinstance(self.embedder, TfidfLsaEmbedder) else "st"
        self.embedder.save(directory / f"embedder.{kind}")
        (directory / "meta.json").write_text(
            json.dumps({"embedder": self.embedder.name, "n_chunks": len(self.chunks),
                        "dim": int(self.embeddings.shape[1])}, indent=1),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, directory: Path = INDEX_DIR) -> "VectorIndex":
        chunks = json.loads((directory / "chunks.json").read_text(encoding="utf-8"))
        emb = np.load(directory / "embeddings.npy")
        if (directory / "embedder.st").exists():
            embedder = SentenceTransformerEmbedder.load(directory / "embedder.st")
        else:
            embedder = TfidfLsaEmbedder.load(directory / "embedder.tfidf")
        return cls(chunks, emb, embedder)

    # ---------------------------------------------------------------- metadata helpers
    def _actor_lexicon(self) -> dict[str, str]:
        lex = {}
        for c in self.chunks:
            if c["actor"] == "generic":
                continue
            for name in [c["actor"], *c.get("aliases", [])]:
                if len(name) >= 4 and not name.lower().startswith(("lockbit 2", "vice society")):
                    lex[name.lower()] = c["actor"]
        return lex

    def actors(self) -> list[str]:
        """Canonical actor list (CISA names; MITRE-only families added when not already covered)."""
        cisa = {c["actor"] for c in self.chunks if c["source_type"] == "cisa_advisory" and c["actor"] != "generic"}
        out = set(cisa)
        for c in self.chunks:
            if c["source_type"] == "mitre_software":
                names = [c["actor"].lower(), *[a.lower() for a in c.get("aliases", [])]]
                if not any(n in a.lower() or a.lower() in n for a in cisa for n in names):
                    out.add(c["actor"])
        return sorted(out)

    def sectors(self) -> list[str]:
        return sorted({s for c in self.chunks for s in c.get("sectors", [])})

    def detect_actors(self, query: str) -> list[str]:
        q = query.lower()
        found = []
        for name, actor in sorted(self.actor_names.items(), key=lambda kv: -len(kv[0])):
            if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", q) and actor not in found:
                found.append(actor)
        return found

    def _same_actor(self, chunk_actor: str, wanted: str) -> bool:
        a, w = chunk_actor.lower(), wanted.lower()
        if a == w or w in a or a in w:
            return True
        # MITRE software "BlackCat" == CISA "ALPHV Blackcat"
        return self.actor_names.get(w) == chunk_actor or self.actor_names.get(a) == wanted

    def _passes(self, c: dict, f: dict) -> bool:
        if f.get("actor"):
            wanted = f["actor"]
            aliases = [x.lower() for x in c.get("aliases", [])]
            if c["actor"] == "generic" or not (self._same_actor(c["actor"], wanted) or wanted.lower() in aliases):
                return False
        if f.get("sector") and f["sector"] not in c.get("sectors", []):
            return False
        if f.get("source_type") and c["source_type"] != f["source_type"]:
            return False
        if f.get("technique"):
            t = f["technique"].upper()
            if not any(x == t or x.startswith(t + ".") for x in c["techniques"]):
                return False
        if f.get("tactic") and f["tactic"] not in c.get("tactics", []):
            return False
        return True

    # ---------------------------------------------------------------- search
    def search(self, query: str, k: int = 6, filters: dict | None = None, mode: str | None = None,
               actor_boost: bool = True) -> list[Hit]:
        filters = {key: v for key, v in (filters or {}).items() if v}
        mode = mode or self.mode
        mask = np.array([self._passes(c, filters) for c in self.chunks])
        if not mask.any():
            return []

        dense = self.embeddings @ self.embedder.encode([query], is_query=True)[0]
        sparse = np.asarray(self.bm25.get_scores(tokenize(query)), dtype=np.float32)
        if sparse.max() > 0:
            sparse = sparse / sparse.max()
        dense01 = np.clip(dense, 0, None)
        if mode == "dense":
            score = dense01.copy()
        elif mode == "bm25":
            score = sparse.copy()
        else:
            score = HYBRID_ALPHA * dense01 + (1 - HYBRID_ALPHA) * sparse

        # Metadata-aware boost: if the question names an actor, favour that actor's chunks
        if actor_boost and mode == "hybrid" and not filters.get("actor"):
            named = self.detect_actors(query)
            if named:
                boost = np.array([0.25 if any(self._same_actor(c["actor"], a) for a in named) else 0.0
                                  for c in self.chunks], dtype=np.float32)
                score = score + boost

        # Section-aware boost: "initial access", "mitigations", "detection", "exfiltration" ...
        if mode == "hybrid":
            q_toks = set(tokenize(query))
            boost = np.array([0.15 if (st := set(tokenize(c["section"]))) and st <= q_toks else 0.0
                              for c in self.chunks], dtype=np.float32)
            score = score + boost

        # MITRE software profiles are long technique lists; damp them so CISA narrative ranks first
        prior = np.array([0.85 if c["source_type"] == "mitre_software" else 1.0 for c in self.chunks], dtype=np.float32)
        score = score * prior

        score = np.where(mask, score, -1.0)
        order = np.argsort(-score)[:k]
        hits = []
        for rank, i in enumerate(order, start=1):
            if score[i] <= 0:
                break
            hits.append(Hit(self.chunks[i], float(score[i]), float(dense[i]), float(sparse[i]), rank, f"S{rank}"))
        return hits


_INDEX: VectorIndex | None = None


def get_index() -> VectorIndex:
    """Load the persisted index, building it on first use if it does not exist yet."""
    global _INDEX
    if _INDEX is None:
        if (INDEX_DIR / "embeddings.npy").exists():
            _INDEX = VectorIndex.load(INDEX_DIR)
        else:
            _INDEX = VectorIndex.build()
            _INDEX.save(INDEX_DIR)
    return _INDEX
