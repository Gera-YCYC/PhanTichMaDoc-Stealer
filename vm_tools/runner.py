"""Only fixed executable argv from trusted configuration, with time/output limits."""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
import signal
import sys
from pathlib import Path


def bounded_process(argv: list[str], work_dir: Path, timeout: int = 90, max_bytes: int = 2_000_000,
                    strict_stderr: bool = False, memory_limit: bool = False,
                    env_overrides: dict | None = None, address_space_limit: int = 1_500_000_000) -> str:
    if not argv or not Path(argv[0]).is_absolute() or not Path(argv[0]).is_file():
        raise FileNotFoundError("Configured analysis executable is unavailable")
    work_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt" and memory_limit:
        if type(address_space_limit) is not int or not 1_500_000_000 <= address_space_limit <= 4_000_000_000:
            raise ValueError('Unsupported analysis address-space limit')
        argv = [sys.executable, "-m", "vm_tools.child_limits", str(address_space_limit), *argv]
    with tempfile.TemporaryDirectory(prefix="tool_", dir=work_dir) as temp:
        stdout_path, stderr_path = Path(temp) / "stdout.txt", Path(temp) / "stderr.txt"
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            proc = subprocess.Popen(argv, cwd=temp, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    shell=False, start_new_session=(os.name != "nt"),
                                    env=({**os.environ, **env_overrides} if env_overrides else None),
                                    creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            started = time.monotonic()
            try:
                while proc.poll() is None:
                    if time.monotonic() - started > timeout:
                        raise TimeoutError("Analysis tool timed out")
                    if stdout_path.stat().st_size + stderr_path.stat().st_size > max_bytes:
                        raise ValueError("Analysis tool output exceeded limit")
                    time.sleep(0.05)
            finally:
                if proc.poll() is None:
                    if os.name == "nt":
                        proc.kill()
                    else:
                        os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=10)
        if stdout_path.stat().st_size + stderr_path.stat().st_size > max_bytes:
            raise ValueError("Analysis tool output exceeded limit")
        if proc.returncode:
            detail = stderr_path.read_text(encoding="utf-8", errors="replace")[-500:]
            raise RuntimeError(f"Analysis tool exited {proc.returncode}: {detail}")
        if strict_stderr and stderr_path.stat().st_size:
            raise RuntimeError("Tool emitted diagnostics; partial output is not accepted: " +
                               stderr_path.read_text(encoding="utf-8", errors="replace")[:400])
        return stdout_path.read_text(encoding="utf-8", errors="replace")
