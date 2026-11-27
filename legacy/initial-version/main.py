"""Điểm vào CLI của hệ thống AI Agent phân tích tĩnh InfoStealer (.NET & Python)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent import DeterministicMockLLM, LLMClientError, OllamaClient, ReActMalwareAgent, ReasoningStep
from config import MAX_ITERATIONS, OLLAMA_BASE_URL, OLLAMA_MODEL, REPORTS_DIR
from reporting import ReportGenerator

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _RICH_AVAILABLE = True
except Exception:
    _RICH_AVAILABLE = False

DEFAULT_DEMO_SAMPLE = Path(__file__).resolve().parent / "samples" / "benign_stealer_sim.py"


def _configure_stdio_utf8() -> None:
    """Đảm bảo in tiếng Việt và ký tự Unicode ổn định trên terminal Windows."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AI Agent tự động phân tích tĩnh mã độc InfoStealer (.NET & Python) theo kiến trúc ReAct."
    )
    parser.add_argument(
        "sample",
        nargs="?",
        default=None,
        help="Đường dẫn tới mẫu nghi ngờ (.exe, .dll, .py, .pyc). Bỏ trống nếu dùng --demo.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Chạy kiểm thử nhanh với mẫu giả lập an toàn `samples/benign_stealer_sim.py`.",
    )
    parser.add_argument(
        "--model",
        default=OLLAMA_MODEL,
        help=f"Tên model Ollama chạy cục bộ (mặc định: {OLLAMA_MODEL}).",
    )
    parser.add_argument(
        "--ollama-url",
        default=OLLAMA_BASE_URL,
        help=f"Địa chỉ Ollama HTTP API (mặc định: {OLLAMA_BASE_URL}).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=MAX_ITERATIONS,
        help=f"Số vòng lặp ReAct tối đa (mặc định: {MAX_ITERATIONS}).",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPORTS_DIR),
        help=f"Thư mục lưu báo cáo JSON & Markdown (mặc định: {REPORTS_DIR}).",
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Dùng DeterministicMockLLM để chạy kiểm thử toàn luồng mà không cần Ollama daemon.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="In từng bước Thought / Action / Observation ra console theo thời gian thực.",
    )
    return parser


def _print_step_plain(step: ReasoningStep) -> None:
    print(f"\n--- [Bước {step.iteration}] {step.action} ({step.elapsed_ms} ms | self-fix={step.self_corrections}) ---")
    print(f"Thought     : {step.thought}")
    print(f"Action Input: {step.action_input}")
    preview = step.observation[:450] + ("..." if len(step.observation) > 450 else "")
    print(f"Observation : {preview}")


def _display_summary(result, json_path: Path, md_path: Path) -> None:
    fa = result.final_analysis
    ioc_count = sum(len(v) for v in fa.iocs.values())

    if _RICH_AVAILABLE:
        console = Console()
        color = "red" if fa.verdict == "MALICIOUS" else ("yellow" if fa.verdict == "SUSPICIOUS" else "green")
        summary_text = (
            f"[bold]Mẫu:[/bold] {result.sample_path}\n"
            f"[bold]Định dạng:[/bold] {result.file_type}\n"
            f"[bold]Model SLM:[/bold] {result.model_name}\n"
            f"[bold]Kết luận (Verdict):[/bold] [{color}]{fa.verdict}[/{color}] "
            f"(Risk: {fa.risk_score}/100 | Confidence: {fa.confidence})\n"
            f"[bold]Vòng lặp ReAct:[/bold] {result.iterations_used} (self-corrections: {result.total_self_corrections}) trong {result.elapsed_seconds}s\n"
            f"[bold]Tóm tắt:[/bold] {fa.behavior_summary}"
        )
        console.print(Panel(summary_text, title="Kết Quả Phân Tích InfoStealer", border_style=color))

        if fa.mitre_attack:
            table = Table(title="MITRE ATT&CK Mapping")
            table.add_column("ID", style="cyan")
            table.add_column("Kỹ thuật")
            table.add_column("Tactic", style="magenta")
            for tech in fa.mitre_attack:
                table.add_row(tech.technique_id, tech.name, tech.tactic)
            console.print(table)

        console.print(f"[bold green]IOCs trích xuất:[/bold green] {ioc_count} | [bold green]YARA matches:[/bold green] {len(result.yara_matches)}")
        console.print(f"[bold]Báo cáo JSON:[/bold] {json_path}")
        console.print(f"[bold]Báo cáo Markdown:[/bold] {md_path}")
        return

    print("\n" + "=" * 72)
    print("KET QUA PHAN TICH INFOSTEALER (STATIC REACT AGENT)")
    print("=" * 72)
    print(f"Mau           : {result.sample_path}")
    print(f"Dinh dang     : {result.file_type}")
    print(f"Model SLM     : {result.model_name}")
    print(f"Verdict       : {fa.verdict} (Risk Score: {fa.risk_score}/100 | Confidence: {fa.confidence})")
    print(f"ReAct Steps   : {result.iterations_used} (self-corrections: {result.total_self_corrections}) | {result.elapsed_seconds}s")
    print(f"IOCs / YARA   : {ioc_count} IOCs | {len(result.yara_matches)} YARA rules matched")
    print(f"Behavior      : {fa.behavior_summary}")
    if fa.mitre_attack:
        tids = ", ".join(f"{t.technique_id} ({t.tactic})" for t in fa.mitre_attack)
        print(f"MITRE ATT&CK  : {tids}")
    print(f"Report JSON   : {json_path}")
    print(f"Report MD     : {md_path}")
    print("=" * 72)


def main() -> int:
    _configure_stdio_utf8()
    parser = _build_arg_parser()
    args = parser.parse_args()

    if args.demo or args.sample is None:
        if not args.demo and args.sample is None:
            print("[INFO] Chưa chỉ định đường dẫn mẫu; tự động dùng chế độ `--demo` với mẫu giả lập an toàn.")
        sample_path = DEFAULT_DEMO_SAMPLE
    else:
        sample_path = Path(args.sample).expanduser().resolve()

    if not sample_path.exists() or not sample_path.is_file():
        print(f"[ERROR] Không tìm thấy file mẫu hợp lệ: {sample_path}", file=sys.stderr)
        return 1

    if args.mock_llm:
        llm_client = DeterministicMockLLM()
        print(f"[INFO] Đang chạy ở chế độ Mock SLM ({llm_client.model_name}).")
    else:
        ollama_client = OllamaClient(base_url=args.ollama_url, model=args.model)
        ok, msg = ollama_client.check_connection()
        if not ok:
            print(f"[ERROR] {msg}", file=sys.stderr)
            return 2
        print(f"[INFO] {msg}")
        llm_client = ollama_client

    step_callback = _print_step_plain if args.verbose else None
    agent = ReActMalwareAgent(
        llm_client=llm_client,
        max_iterations=args.max_iterations,
        on_step=step_callback,
    )

    print(f"[INFO] Bắt đầu điều tra tĩnh mẫu: {sample_path} (max_iterations={args.max_iterations})")
    try:
        result = agent.analyze(str(sample_path))
    except LLMClientError as exc:
        print(f"[ERROR] Lỗi giao tiếp với Local SLM: {exc}", file=sys.stderr)
        return 3

    json_path, md_path = ReportGenerator.generate(result, output_dir=Path(args.output_dir))
    _display_summary(result, json_path, md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
