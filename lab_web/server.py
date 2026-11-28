"""Loopback UI. Browser inputs never become commands, paths or arbitrary VM actions."""

import argparse
import json
from hashlib import sha256
import os
import re
import secrets
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .cases import ROOT, case, directory, history, read, samples
from stealer_agent.transport import OllamaClient, ToolClient

CFG = "config/host.investigation.example.json"
STATIC = Path(__file__).with_name("static")
LOCK = threading.Lock()
JOB = {"active": False, "lines": []}
KEY = secrets.token_urlsafe(32)


def training_record():
    folder = ROOT / "training/experiments/20261127T153436999877Z"
    receipt = read(folder / "receipt.json")
    for file, field in [(folder / "model.json", "model_sha256"),
                        (ROOT / "vm_tools/code_ranker.json", "model_sha256"),
                        (ROOT / "training/corpus/code-reference-v1.json", "dataset_sha256"),
                        (ROOT / "training/train_ranker.py", "trainer_sha256")]:
        if sha256(file.read_bytes()).hexdigest() != receipt[field]:
            raise ValueError("Hash của hồ sơ huấn luyện không khớp.")
    config = read(folder / "config.json")
    loss = read(folder / "loss.json")
    if [item["epoch"] for item in loss] != list(range(config["epochs"] + 1)):
        raise ValueError("Chuỗi bước train bị thiếu.")
    return {"run": receipt["run_id"], "config": config, "metrics":receipt["metrics"],
            "model_sha256": receipt["model_sha256"], "dataset_sha256": receipt["dataset_sha256"],
            "loss_start":loss[0]["train_binary_cross_entropy_plus_l2"],
            "loss_end":loss[-1]["train_binary_cross_entropy_plus_l2"]}


def token():
    return (ROOT / "config/lab.token").read_text(encoding="utf-8-sig").strip()


def health():
    cfg = {**read(ROOT / CFG), "timeout_s": 3}
    result = {"model": cfg["model"], "ollama": False, "vm": False, "tools": []}
    try:
        info = OllamaClient(cfg).inspect()
        result.update(ollama=True, digest=info["digest"])
    except (OSError, ValueError, RuntimeError):
        pass
    try:
        vm = ToolClient(cfg, token()).inspect()
        result.update(
            vm=True,
            tools=sorted(
                k for k, v in vm["tools"].items() if v.get("available") is True
            ),
        )
    except (OSError, ValueError, RuntimeError):
        pass
    return result


def reserve(kind):
    with LOCK:
        if JOB["active"]:
            raise ValueError("Có tác vụ đang chạy. Chờ tác vụ hiện tại hoàn tất.")
        JOB.clear()
        JOB.update(kind=kind, active=True, lines=[], run=None, error=None)


def start(kind, sample):
    if sample not in samples() or kind not in ("analyze", "yara"):
        raise ValueError("Lựa chọn không hợp lệ.")
    key = token()
    reserve(kind)
    with LOCK:
        JOB["sample"] = sample if kind == "analyze" else "real-v3"

    def work():
        ok = False
        try:
            if kind == "analyze":
                args = [
                    "agent_react.py",
                    "--config",
                    CFG,
                    "--sample",
                    sample,
                    "--public-demo",
                    "--live",
                    "--with-yara",
                ]
            else:
                args = [
                    "-m",
                    "stealer_agent.yara_corpus",
                    "--config",
                    CFG,
                    "--profile",
                    "real-v3",
                    "--manifest",
                    "eval/corpora/real-yara-development-v3.json",
                ]
            with subprocess.Popen(
                [sys.executable, "-u", *args],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf8",
                errors="replace",
                env={
                    **os.environ,
                    "PYTHONIOENCODING": "utf-8",
                    "STEALER_LAB_TOKEN": key,
                },
            ) as child:
                for raw in child.stdout:
                    line = raw.strip()
                    with LOCK:
                        if line.startswith("[RUN]"):
                            JOB["run"] = Path(line.rsplit(" | ", 1)[-1]).name
                        if line.startswith(
                            (
                                "[RUN]",
                                "[STEP",
                                "[GAP",
                                "[YARA]",
                                "[READY]",
                                "[DONE]",
                                "[LIMIT]",
                                "[REPORT]",
                                "[REVIEW]",
                                "[ERROR]",
                            )
                        ):
                            JOB["lines"].append(
                                "Mở lượt " + str(JOB["run"])
                                if line.startswith("[RUN]")
                                else line[:220]
                            )
                        if kind == "yara" and line.startswith("{"):
                            result = json.loads(line)
                            folder = Path(result.get("run_directory", "")).resolve()
                            if folder.parent == ROOT / "runs" and re.fullmatch(
                                r"yara_real_[0-9a-f]{12}", folder.name
                            ):
                                JOB["yara_run"] = folder.name
                ok = child.wait() == 0
        finally:
            with LOCK:
                JOB.update(
                    active=False,
                    error=None
                    if ok
                    else "Lượt chạy chưa hoàn tất. Kiểm tra trạng thái lab và nhật ký.",
                )

    threading.Thread(target=work, daemon=False).start()


def yara_history():
    from .yara_view import attempts

    rows = []
    for p in sorted(
        (ROOT / "runs").glob("yara_real_*/summary.private.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        r = read(p)
        if r.get("profile") != "real-v3":
            continue
        frozen = p.parent / "generated.yar"
        rule_text = None
        if frozen.is_file() and frozen.stat().st_size <= 6000:
            rule = frozen.read_text(encoding="utf8")
            if sha256(rule.encode()).hexdigest() == (r.get("development") or {}).get(
                "rule_sha256"
            ):
                rule_text = rule
        rows.append(
            {
                "run": p.parent.name,
                "status": r.get("status"),
                "model": r.get("model"),
                "rules": r.get("rule_count"),
                "rule_text": rule_text,
                "tpr": (r.get("development") or {}).get("tpr"),
                "fpr": (r.get("holdout") or {}).get("fpr"),
                "attempts": attempts(p.parent / "events.jsonl", r),
            }
        )
    return rows


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, data, kind="application/json"):
        if kind == "application/json":
            data = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def route(self, post=False):
        origin = "http://127.0.0.1:" + str(self.server.server_port)
        if (
            self.headers.get("Host") != origin[7:]
            or self.headers.get("Sec-Fetch-Site") == "cross-site"
        ):
            return self.reply(403, {"error": "Chỉ truy cập từ máy này."})
        p = self.path
        if post:
            if self.headers.get("Origin") != origin or not secrets.compare_digest(
                self.headers.get("X-Lab-Key", ""), KEY
            ):
                # Drain a small declared body before closing. On Windows an unread
                # POST can otherwise reset the socket ahead of the 403 response.
                length = self.headers.get("Content-Length", "")
                if length.isascii() and length.isdecimal() and len(length) <= 4 and int(length) <= 4096:
                    self.connection.settimeout(1)
                    try:
                        self.rfile.read(int(length))
                    except TimeoutError:
                        pass
                return self.reply(403, {"error": "Phiên trình duyệt không hợp lệ."})
            n = int(self.headers.get("Content-Length", "0"))
            if (
                not 0 < n <= 4096
                or self.headers.get_content_type() != "application/json"
            ):
                return self.reply(400, {"error": "Dữ liệu yêu cầu không hợp lệ."})
            data = json.loads(self.rfile.read(n))
            if not isinstance(data, dict):
                raise ValueError("Yêu cầu phải là đối tượng JSON.")
            if p == "/api/close":
                if not getattr(self.server, "managed_lab", False):
                    return self.reply(
                        409,
                        {
                            "error": "Phiên này chỉ xem lịch sử hoặc do một tiến trình khác quản lý."
                        },
                    )
                reserve("close")
                try:
                    return self.reply(202, {"accepted": True})
                finally:
                    self.server.shutdown()
            if getattr(self.server, "history_only", False) and p in (
                "/api/analyze",
                "/api/yara",
                "/api/question",
                "/api/claim-review",
                "/api/dotnet-supplement",
                "/api/field-review",
            ):
                return self.reply(
                    409, {"error": "Chế độ xem lịch sử. Mở Start-Web.ps1 để dùng lab."}
                )
            if p in ("/api/analyze", "/api/yara"):
                start(p.rsplit("/", 1)[1], data.get("sample"))
                return self.reply(202, {"accepted": True})
            if p == "/api/dotnet-supplement":
                from .dotnet_supplement import generate
                reserve("dotnet-supplement")
                try:
                    return self.reply(200, generate(data.get("run"), read(ROOT / CFG), token()))
                finally:
                    with LOCK:
                        JOB.update(active=False)
            if p == "/api/field-review":
                from .field_review import review
                reserve("field-review")
                try:
                    return self.reply(200, review(data, read(ROOT / CFG), token()))
                finally:
                    with LOCK:
                        JOB.update(active=False)
            if p == "/api/claim-review":
                from .claim_review import revisit
                reserve("claim-review")
                try:
                    return self.reply(200, revisit(data, read(ROOT / CFG)))
                finally:
                    with LOCK:
                        JOB.update(active=False)
            if p == "/api/question":
                from .review import answer

                reserve("question")
                try:
                    return self.reply(200, answer(data, read(ROOT / CFG), token()))
                finally:
                    with LOCK:
                        JOB.update(active=False)
            if p == "/api/label":
                from .review import label

                return self.reply(200, label(data))
        else:
            if p in ("/", "/app.js", "/styles.css"):
                name = "index.html" if p == "/" else p[1:]
                mime = {
                    "index.html": "text/html",
                    "app.js": "application/javascript",
                    "styles.css": "text/css",
                }[name]
                return self.reply(200, (STATIC / name).read_bytes(), mime)
            if p == "/api/init":
                return self.reply(
                    200,
                    {
                        "key": KEY,
                        "history_only": getattr(self.server, "history_only", False),
                        "managed_lab": getattr(self.server, "managed_lab", False),
                        "samples": {
                            k: {"branch": v["branch"], "bytes": v["size_bytes"]}
                            for k, v in samples().items()
                        },
                        "history": history(),
                    },
                )
            if p == "/api/health":
                return self.reply(200, health())
            if p == "/api/job":
                with LOCK:
                    snapshot = {**JOB, "lines": list(JOB["lines"])}
                return self.reply(200, snapshot)
            if p == "/api/yara":
                return self.reply(200, yara_history())
            if p == "/api/training":
                return self.reply(200, training_record())
            if p == "/api/evaluation":
                from eval.web_report_quality import current_batch, dotnet_profiles, reports

                base = ROOT / "deliverables/real-demo-evidence"
                rubric = read(base / "coverage-v11-rubric.json")
                paired = read(base / "web-comparison.json")
                repeats = base / "web-stability-python.json"
                return self.reply(
                    200,
                    {
                        "rubric": {
                            k: rubric[k]
                            for k in (
                                "raw",
                                "after_filter",
                                "total_attempts",
                                "correct_verdicts",
                            )
                        },
                        "search": [
                            {
                                "sample": row["sample"],
                                "mode": row["mode"],
                                "found": len(row["covered"]),
                                "missed": len(row["missed"]),
                                "wrong": row["wrong_producer_at_graded_site"],
                                "tool_calls": row["tool_calls"],
                                "model_calls": row["model_calls"],
                                "seconds": row["elapsed_s"],
                            }
                            for row in paired["results"]
                        ],
                        "stability": read(repeats) if repeats.exists() else None,
                        "web_report_quality": reports(),
                        "dotnet_quality": {key: reports(sample=key) for key in dotnet_profiles()},
                        "current_batch": current_batch(),
                        "card_supplements": read(base / "web-card-supplements.json"),
                        "cng_trial": read(base / "web-cng-review.json"),
                        "narrow_trials": read(base / "web-narrow-review.json"),
                        "dotnet_followup": read(base / "web-dotnet-followup.json")["samples"],
                        "followup_reports": read(base / "web-dotnet-followup-reports.json"),
                    },
                )
            if p == "/api/yara/regression":
                from .yara_view import regression

                return self.reply(200, regression(ROOT))
            if p.startswith("/api/case/"):
                return self.reply(200, case(p[len("/api/case/") :]))
        self.reply(404, {"error": "Không tìm thấy."})

    def handle_method(self, post):
        try:
            self.route(post)
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass
        except (ValueError, OSError, RuntimeError, KeyError, TypeError) as e:
            self.reply(
                400,
                {
                    "error": str(e)[:220]
                    if type(e) is ValueError
                    else "Không đọc được bằng chứng hoặc dịch vụ lab. Kiểm tra VM, model và lượt chạy."
                },
            )

    def do_GET(self):
        self.handle_method(False)

    def do_POST(self):
        self.handle_method(True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=4180)
    p.add_argument("--history-only", action="store_true")
    p.add_argument(
        "--managed-lab",
        action="store_true",
        help="Launcher will stop its lab after normal server exit",
    )
    args = p.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.history_only = args.history_only
    server.managed_lab = args.managed_lab and not args.history_only
    print(f"StealerLab · http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
