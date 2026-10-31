import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("LLM_PROVIDER", "none")
os.environ.setdefault("EMBEDDING_BACKEND", "tfidf")


@pytest.fixture(scope="session", autouse=True)
def isolated_logs(tmp_path_factory):
    from ransomrag import config

    config.LOG_DIR = tmp_path_factory.mktemp("logs")
    import ransomrag.monitoring as mon

    mon.LOG_DIR = config.LOG_DIR
    yield


@pytest.fixture(scope="session")
def index():
    from ransomrag.vectorstore import get_index

    return get_index()


@pytest.fixture(scope="session")
def kb():
    from ransomrag.attack import get_kb

    return get_kb()
