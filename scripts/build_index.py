"""Build the full pipeline: chunks -> embeddings -> persisted vector index.

Usage: python scripts/build_index.py [--backend auto|sentence-transformers|tfidf]
"""
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ransomrag import ingest  # noqa: E402
from ransomrag.config import INDEX_DIR  # noqa: E402
from ransomrag.vectorstore import VectorIndex  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default=None)
    args = ap.parse_args()
    t0 = time.time()
    ingest.main()
    idx = VectorIndex.build(backend=args.backend)
    idx.save(INDEX_DIR)
    print(f"Index built with {idx.embedder.name}: {len(idx.chunks)} chunks, dim={idx.embeddings.shape[1]} "
          f"in {time.time() - t0:.1f}s -> {INDEX_DIR.relative_to(ROOT)}")
