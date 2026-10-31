"""Entry point: python app.py  ->  http://localhost:7860"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from ransomrag.ui import build_ui  # noqa: E402

if __name__ == "__main__":
    build_ui().launch(
        server_name=os.getenv("GRADIO_SERVER_NAME", "127.0.0.1"),
        server_port=int(os.getenv("GRADIO_SERVER_PORT", "7860")),
    )
