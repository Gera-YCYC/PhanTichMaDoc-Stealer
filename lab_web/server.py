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
from stealer_agent.telemetry import available_memory_bytes

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
    from scripts.compare_ranker_runs import reviewed_metrics
    base = ROOT / "deliverables/real-demo-evidence"
    pair = read(base / "agenttesla-ranker-ablation.json")
    before, after = pair["before"], pair["after"]
    if (before["run_id"] == after["run_id"] or before["backend_ranker_sha256"] is not None
            or after["backend_ranker_sha256"] != receipt["model_sha256"]
            or any(before[k] != after[k] for k in ("sample_sha256", "shared_config_sha256", "source_manifest_sha256", "model_digest"))
            or before["source_review"]["reference_sha256"] != after["source_review"]["reference_sha256"]):
        raise ValueError("Điều kiện đối chứng của hai lượt xếp hạng khác nhau.")
    comparison = []
    for arm in (before, after):
        grades = reviewed_metrics(arm, base, verify_private=False)
        if grades != arm["source_review"]:
            raise ValueError("Điểm của lượt xếp hạng khác hồ sơ nguồn.")
        comparison.append({"run": arm["run_id"], "verdict": arm["verdict"], "searches": arm["code_searches"],
                           "hits": arm["nonempty_code_searches"], "tools": arm["metrics"]["tool_calls"],
                           "seconds": arm["metrics"]["elapsed_s"], "score": grades["after_filter"]})
    return {"run": receipt["run_id"], "comparison": comparison, "config": config, "metrics":receipt["metrics"],
            "model_sha256": receipt["model_sha256"], "dataset_sha256": receipt["dataset_sha256"],
            "loss_start":loss[0]["train_binary_cross_entropy_plus_l2"],
            "loss_end":loss[-1]["train_binary_cross_entropy_plus_l2"]}


def token():
    return (ROOT / "config/lab.token").read_text(encoding="utf-8-sig").strip()


def health():
    cfg = {**read(ROOT / CFG), "timeout_s": 3}
    result = {"model": cfg["model"], "ollama": False, "vm": False, "tools": [],
              "free_host_bytes": available_memory_bytes(),
              "memory_floor_bytes": cfg.get("minimum_free_ram_mb", 256) * 1024 * 1024}
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
                ]
                from stealer_agent.demo_samples import MALWARE
                if samples()[sample]["evidence_kind"] == MALWARE:
                    args.append("--with-yara")
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
                from eval.argument_review import review as argument_review
                from eval.cross_format import published as cross_format
                from eval.table_access_study import METHOD_RESULT, method_result, published as table_access
                from eval.ordinal_review_study import PUBLIC as ordinal_receipt, published as ordinal_study
                from eval.catch_argument_study import PUBLIC as catch_receipt, published as catch_study
                from eval.catch_clean_controls import PUBLIC as control_receipt, published as catch_controls
                from eval.role_line_study import PUBLIC as roles_receipt, web_results as role_study
                from eval.send_site_study import OUT as send_receipt, check as send_score
                from eval.link_source_study import OUT as link_receipt, check as link_score, live_comparison
                from eval.parts_audit import PUBLIC as parts_receipt, score as score_parts, web_details
                from eval.report_series import ARGUMENT_SERIES, web_results
                from eval.verdict_trial import PUBLIC as verdict_receipt, score as score_verdict
                from eval.web_report_quality import current_batch, dotnet_profiles, reports

                base = ROOT / "deliverables/real-demo-evidence"
                parts = read(parts_receipt)
                rubric = read(base / "coverage-v11-rubric.json")
                paired = read(base / "web-comparison.json")
                repeats = base / "web-stability-python.json"
                staging = read(base / "staging-path-python.json")
                path_trials = []
                for run in [r["run"] for r in staging["runs"]] + [staging["repeat_run"]]:
                    grade = read(base / f"transfer-live-{run}.json")["graded_score"]
                    live = read(base / f"web-{run}.json")
                    edge = next(e for e in live["terminal_edges"] if e["id"] == "write-archive")
                    path_trials.append({
                        "run": run, "verified": bool(edge.get("path_check")), "score": grade,
                        "tools": live["metrics"]["tool_calls"], "seconds": live["metrics"]["elapsed_s"],
                    })
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
                        "current_stability": web_results(),
                        "argument_stability": web_results(ARGUMENT_SERIES),
                        "argument_batch": cross_format(),
                        "reader_comparison": table_access(),
                        "ordinal_review": ordinal_study() if ordinal_receipt.is_file() else None,
                        "catch_study": catch_study() if catch_receipt.is_file() else None,
                        "catch_controls": catch_controls()["controls"] if control_receipt.is_file() else [],
                        "role_line_study": role_study() if roles_receipt.is_file() else [],
                        "intact_methods": method_result() if METHOD_RESULT.is_file() else None,
                        "verdict_format_trial": score_verdict(read(verdict_receipt)),
                        "argument_review": argument_review(),
                        "split_scores": score_parts(parts),
                        "split_details": web_details(parts),
                        "split_a09": parts["a09_source"],
                        "web_report_quality": reports(),
                        "dotnet_quality": {key: reports(sample=key) for key in dotnet_profiles()},
                        "current_batch": current_batch(),
                        "transfer_comparison": read(base / "transfer-report-comparison.json")["scores"],
                        "staging_trials": path_trials,
                        "send_site_retrieval": send_score(read(send_receipt)),
                        "link_source_study": link_score(read(link_receipt)),
                        "link_live_comparison": live_comparison(),
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
