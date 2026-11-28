"""Local, read-only views of genuine completed or unsuccessful public sample runs."""

import json
import re
from functools import lru_cache
from pathlib import Path
from hashlib import sha256
from vm_tools.code_search import structural_features
from stealer_agent.investigation import CODE, excerpt, ledger
from stealer_agent.journal import verify_journal
from stealer_agent.redaction import redact_document

ROOT = Path(__file__).resolve().parents[1]
RUN = re.compile(r"\d{8}T\d{6}_[a-f0-9]{8}")


def read(path):
    return json.loads(path.read_bytes())


def samples():
    return read(ROOT / "config/public-samples.json")["samples"]


def directory(run):
    if not isinstance(run, str) or not RUN.fullmatch(run):
        raise ValueError("Mã lượt chạy không hợp lệ.")
    folder = (ROOT / "runs" / run).resolve()
    if folder.parent != (ROOT / "runs").resolve() or not folder.is_dir():
        raise ValueError("Không tìm thấy lượt chạy.")
    return folder


def trusted_report(run):
    data = read(directory(run) / "report.redacted.json")
    sha = samples().get(data.get("sample"), {}).get("sha256")
    if (
        not sha
        or data.get("run_id") != run
        or data.get("sample_sha256") != sha
        or data.get("evidence_kind") != "real-public-malware-local-slm-vm"
    ):
        raise ValueError("Hồ sơ chưa xác nhận được mẫu công khai.")
    return data


def history():
    base = ROOT / "runs"
    result = []
    for path in sorted(base.glob("*/report.redacted.json"), reverse=True):
        try:
            r = trusted_report(path.parent.name)
        except (ValueError, OSError):
            continue
        result.append(
            {
                "run": r["run_id"],
                "sample": r["sample"],
                "model": r["model"]["tag"],
                "status": r["status"],
            }
        )
    return result


def absorb(records, obs):
    if obs.get("tool") not in CODE or obs.get("status") != "ok":
        return
    eid = obs["evidence_id"]
    rec = records.setdefault(
        eid,
        {
            k: obs[k]
            for k in ("evidence_id", "tool", "sample_sha256", "output_sha256", "status")
        },
    )
    if (
        rec["output_sha256"] != obs["output_sha256"]
        or rec["sample_sha256"] != obs["sample_sha256"]
    ):
        raise ValueError("Nguồn trích dẫn thay đổi.")
    rec.setdefault("line_map", {}).update({r["line"]: r["text"] for r in obs["lines"]})
    facts = rec.setdefault("operation_facts", [])
    if "archive_link" in obs:
        rec["archive_link"] = obs["archive_link"]
    for f in obs.get("operation_facts", []):
        if f not in facts:
            facts.append(f)


def review_anchors(raw, projected):
    original = {r["line"]: r for r in raw["lines"]}
    shown = {r["line"]: r["text"] for r in projected["lines"]}
    for group in raw.get("search_groups", []):
        n = group["anchor_line"]
        query = group["query"]
        numbers = range(max(1, n - 3), min(raw["total_lines"], n + 6) + 1)
        if any(i not in original for i in numbers) or n not in shown:
            continue
        rows = [original[i] for i in numbers]
        ref = {
            "eid": raw["evidence_id"],
            "tool": raw["tool"],
            "output_sha256": raw["output_sha256"],
            "line": n,
            "end": n,
            "query": query,
            "text": excerpt(shown[n]),
            "anchor_sha256": sha256(original[n]["text"].encode()).hexdigest(),
            "features": structural_features(rows, n - numbers.start, query),
        }
        ident = sha256(
            json.dumps([ref[k] for k in ("output_sha256", "line", "query")]).encode()
        ).hexdigest()
        yield {"fact": "anchor_" + ident, **ref}


@lru_cache(maxsize=4)
def source(run, fingerprint):
    folder = directory(run)
    log = folder / "events.jsonl"
    verify_journal(log)
    r = trusted_report(run)
    records, timeline, anchors = {}, [], {}
    last = {}
    with log.open(encoding="utf8") as stream:
        for line in stream:
            e = json.loads(line)
            last = e
            kind = e["event"]
            desc = None
            if kind == "observation":
                o = e["model_visible"]
                if o["sample_sha256"] != r["sample_sha256"]:
                    raise ValueError("Mẫu trong nhật ký không khớp báo cáo.")
                absorb(records, o)
                if o.get("tool") in CODE and o.get("status") == "ok":
                    for ref in review_anchors(e["raw"], o):
                        anchors[ref["fact"]] = ref
                desc = f"{o['tool']} · {o['status']} · {len(o.get('lines', []))} dòng"
            elif kind == "action_dispatched":
                desc = e["action"]
            elif kind == "hypothesis_open":
                desc = "Tìm liên kết " + e["edge"]
            elif kind == "hypothesis_result":
                desc = (
                    e["edge"]
                    + " · "
                    + e["status"]
                    + " · "
                    + str(e["hit_count"])
                    + " kết quả tìm"
                )
            elif kind in (
                "preflight",
                "run_started",
                "run_finished",
                "action_rejected",
                "run_error",
            ):
                desc = kind
            if desc:
                timeline.append(
                    {
                        "step": e.get("step"),
                        "time": e["timestamp"],
                        "event": kind,
                        "detail": desc,
                    }
                )
    if last.get("event") != "run_finished" or last["result"] != read(
        folder / "report.private.json"
    ):
        raise ValueError("Nhật ký thiếu bản ghi kết thúc khớp báo cáo.")
    if (
        last["result"]["sample_sha256"] != r["sample_sha256"]
        or last["result"]["model"]["digest"] != r["model"]["digest"]
    ):
        raise ValueError("Thông tin model hoặc mẫu không khớp.")
    saved = last["result"].get("investigation")
    frozen_graph = redact_document(saved)[0] if saved is not None else None
    return records, timeline, list(anchors.values()), frozen_graph


def case(run):
    r = trusted_report(run)
    log = directory(run) / "events.jsonl"
    records, timeline, anchors, frozen_graph = source(
        run, (log.stat().st_size, log.stat().st_mtime_ns)
    )
    graph = (
        frozen_graph
        if frozen_graph is not None
        else ledger(records, r["sample_sha256"])
    )
    analysis = r["analysis"]
    claims = [
        {
            "id": c["id"],
            "text": c.get("statement", c.get("text", "")),
            "refs": [
                {
                    "eid": x["evidence_id"],
                    "line": x["line"],
                    "end": x.get("end_line", x["line"]),
                    "text": excerpt(x["quote"].splitlines()[0]),
                }
                for x in c.get("evidence", [])
            ],
        }
        for c in analysis["claims"]
    ]
    yara = []
    for p in sorted(directory(run).glob("yara/scan_*/result.json")):
        y = read(p)
        if y["analysis_run"] == run and y["sample_sha256"] == r["sample_sha256"]:
            yara.append(
                {
                    k: y[k]
                    for k in (
                        "matched",
                        "rule_names",
                        "yara_version",
                        "dataset_partition",
                        "files_scanned_in_partition",
                    )
                }
            )
    questions = []
    for path in sorted(
        directory(run).glob("questions/q_*/events.jsonl"),
        key=lambda p: p.stat().st_mtime,
    ):
        verify_journal(path)
        with path.open(encoding="utf8") as stream:
            events = [json.loads(line) for line in stream]
        if (
            events
            and events[0].get("run") == run
            and events[-1].get("event") == "answered"
        ):
            questions.append(events[-1]["answer"])
    return {
        "run": run,
        "sample": r["sample"],
        "sha": r["sample_sha256"],
        "model": r["model"]["tag"],
        "status": r["status"],
        "verdict": analysis["verdict"],
        "metrics": {
            k: r["metrics"].get(k)
            for k in (
                "elapsed_s",
                "model_calls",
                "tool_calls",
                "tool_errors",
                "prompt_tokens",
                "completion_tokens",
                "host_peak_rss_bytes",
                "model_vram_bytes_after_run",
                "minimum_observed_host_available_memory_bytes",
                "api_cost_usd",
            )
        },
        "timeline": timeline,
        "graph": graph,
        "graph_origin": "terminal" if frozen_graph is not None else "reconstructed",
        "claims": claims,
        "yara": yara,
        "anchors": anchors,
        "questions": questions,
    }


def records_for(run):
    log = directory(run) / "events.jsonl"
    return source(run, (log.stat().st_size, log.stat().st_mtime_ns))[0]
