"""Cấu hình trung tâm cho hệ thống AI Agent phân tích InfoStealer."""

from __future__ import annotations

import os
from pathlib import Path

# Đường dẫn thư mục dự án
BASE_DIR: Path = Path(__file__).resolve().parent
RULES_DIR: Path = BASE_DIR / "rules"
SAMPLES_DIR: Path = BASE_DIR / "samples"
REPORTS_DIR: Path = BASE_DIR / "reports"
WORK_DIR: Path = Path(os.getenv("STEALER_WORK_DIR", str(BASE_DIR / "workdir")))
DEFAULT_YARA_RULES: Path = RULES_DIR / "infostealer_rules.yar"

# Cấu hình SLM cục bộ (Ollama)
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# Ràng buộc ReAct & quản lý Context Window cho SLM 7B/8B (GGUF Q4_K_M)
MAX_ITERATIONS: int = int(os.getenv("MAX_ITERATIONS", "8"))
MAX_TOOL_OUTPUT_CHARS: int = int(os.getenv("MAX_TOOL_OUTPUT_CHARS", "3500"))
MAX_SNIPPET_CHARS: int = int(os.getenv("MAX_SNIPPET_CHARS", "1200"))

# Cấu hình chạy công cụ ngoài (an toàn & giới hạn thời gian)
SUBPROCESS_TIMEOUT: int = int(os.getenv("SUBPROCESS_TIMEOUT", "60"))
PYINSTXTRACTOR_PATH: str = os.getenv("PYINSTXTRACTOR_PATH", "/opt/tools/pyinstxtractor.py")
