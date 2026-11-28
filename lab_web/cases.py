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
    if "staging_link" in obs:
        rec["staging_link"] = obs["staging_link"]
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


def trace_search(attempts, event):
    """Join observed searches by step. Never infer a past status from the final map."""
    step = event.get("step")
    kind = event["event"]
    if kind == "hypothesis_open":
        if step in attempts:
            raise ValueError("Trùng bước mở giả thuyết.")
        query = event["query"]
        attempts[step] = {
            "step": step,
            "edge": event["edge"],
            "query": query
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_ .(]{0,79}", query)
            else "⟦đã ẩn⟧",
            "anchors": [],
            "status": None,
            "hits": None,
            "tool_status": None,
        }
    elif step in attempts:
        row = attempts[step]
        if kind == "observation":
            obs = event["model_visible"]
            observed = {line["line"] for line in obs.get("lines", [])}
            row["anchors"] = sorted(
                {
                    g["anchor_line"]
                    for g in obs.get("search_groups", [])
                    if g["anchor_line"] in observed
                }
            )
        elif kind == "hypothesis_result":
            if row["edge"] != event["edge"] or row["status"] is not None:
                raise ValueError("Kết quả không khớp bước điều tra.")
            row.update(
                status=event["status"],
                hits=event["hit_count"],
                tool_status=event["tool_status"],
            )


@lru_cache(maxsize=4)
def source(run, fingerprint):
    folder = directory(run)
    log = folder / "events.jsonl"
    verify_journal(log)
    r = trusted_report(run)
    records, timeline, anchors = {}, [], {}
    attempts = {}
    reviewable = set()
    last = {}
    with log.open(encoding="utf8") as stream:
        for line in stream:
            e = json.loads(line)
            trace_search(attempts, e)
            last = e
            kind = e["event"]
            if kind == "card_claim_review" and not e["check"]["supported"]:
                reviewable.add(e["claim_id"])
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
            elif kind == "flow_review_inventory":
                desc = f"Đối chiếu đường truyền · {len(e['routes'])} đề xuất"
            elif kind == "flow_review_decision":
                if re.fullmatch(r"C[1-9][0-9]*", e["claim_id"]):
                    outcome = "có hỗ trợ" if e["decision"]["supported"] else "chưa đủ hỗ trợ"
                    desc = f"Qwen duyệt {e['claim_id']} · {outcome}"
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
    return (
        records,
        timeline,
        list(anchors.values()),
        frozen_graph,
        list(attempts.values()),
        reviewable,
    )


def cited_windows(records, graph, claims):
    """Display only recorded rows around a cited position, retaining visible gaps."""
    windows = {}
    for item in [*graph["nodes"], *graph["edges"], *claims]:
        references = [
            *item.get("refs", []),
            *item.get("leads", []),
            *item.get("trail", []),
            *item.get("path_check", {}).get("refs", []),
        ]
        if item.get("lead"):
            references.append(item["lead"])
        for ref in references:
            eid, start, end = ref["eid"], ref["line"], ref["end"]
            key = f"{eid}:{start}:{end}"
            record = records.get(eid)
            if key in windows or record is None or not 0 < start <= end:
                continue
            if (
                ref.get("output_sha256", record["output_sha256"])
                != record["output_sha256"]
            ):
                continue
            lines = record["line_map"]
            if start not in lines:
                continue
            # Two context rows on either side of a short citation. For long
            # citations label the omitted middle explicitly instead of joining it.
            before, after = max(1, start - 2), end + 2
            spans = (
                [(before, after)]
                if end - start < 48
                else [(before, start + 21), (end - 21, after)]
            )
            rows = [
                [n, excerpt(lines[n]), start <= n <= end]
                for lo, hi in spans
                for n in range(lo, hi + 1)
                if n in lines
            ]
            windows[key] = {
                "tool": record["tool"],
                "output_sha256": record["output_sha256"],
                "rows": rows,
            }
    return windows


def display_claim(c, records, *, rejected=False):
    refs = []
    for ref in c.get("evidence", []):
        eid, line = ref["evidence_id"], ref["line"]
        end = ref.get("end_line", line)
        quote = ref["quote"]
        if rejected:
            # An invalid quote can itself be the reason for rejection. Only
            # offer a source viewer when the displayed quote matches the log.
            rows = records.get(eid, {}).get("line_map", {})
            if not 0 <= end - line < 40 or any(
                n not in rows for n in range(line, end + 1)
            ):
                continue
            actual = "\n".join(rows[n] for n in range(line, end + 1))
            if not quote or (
                quote != actual if "end_line" in ref else quote not in actual
            ):
                continue
        refs.append(
            {
                "eid": eid,
                "line": line,
                "end": end,
                "text": excerpt(quote.split("\n")[0]),
            }
        )
    return {"id": c["id"], "text": c.get("statement", c.get("text", "")), "refs": refs}


def recent_reviews(folder, run, sample_digest, model_digest):
    result = {}
    source_digest = None
    for path in sorted(
        folder.glob("claim-reviews/review_*/events.jsonl"),
        key=lambda p: p.stat().st_mtime_ns,
    ):
        # The UI can read the case while a review is appending. Only terminal
        # snapshots are displayed, and their full chain must verify.
        content = path.read_bytes()
        if not content.endswith(b"\n"):
            continue
        entries = content.splitlines()
        first, last = json.loads(entries[0]), json.loads(entries[-1])
        if (
            first["event"] == "review_started"
            and first["run"] == run
            and first["sample_sha256"] == sample_digest
            and first["model_digest"] == model_digest
            and last["event"] == "review_finished"
        ):
            verify_journal(path)
            if source_digest is None:
                source_digest = sha256(
                    (folder / "events.jsonl").read_bytes()
                ).hexdigest()
            if (
                first["source_journal_sha256"] != source_digest
                or last["display"]["claim"] != first["parent"]
                or last["display"]["id"] != path.parent.name
            ):
                raise ValueError("Lần đọc bổ sung không khớp nhật ký nguồn.")
            result[first["parent"]] = last["display"]
    return result


def case(run):
    r = trusted_report(run)
    log = directory(run) / "events.jsonl"
    records, timeline, anchors, frozen_graph, attempts, reviewable = source(
        run, (log.stat().st_size, log.stat().st_mtime_ns)
    )
    graph = (
        frozen_graph
        if frozen_graph is not None
        else ledger(records, r["sample_sha256"])
    )
    analysis = r["analysis"]
    claims = [display_claim(c, records) for c in analysis["claims"]]
    rejected = []
    prior_reviews = recent_reviews(
        directory(run), run, r["sample_sha256"], r["model"]["digest"]
    )
    for entry in analysis.get("rejected_claims", []):
        c = display_claim(entry["claim"], records, rejected=True)
        rejected.append(
            {
                **c,
                "can_revisit": c["id"] in reviewable
                and entry["claim"]["kind"] == "behavior",
                "revisit": prior_reviews.get(c["id"]),
                "reasons": entry.get("reasons", []),
                "review_note": entry.get("review_note"),
                "unverified_refs": len(entry["claim"].get("evidence", []))
                - len(c["refs"]),
            }
        )
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
    from .dotnet_supplement import latest
    dotnet = any(rec["tool"] == "decompile_dotnet" for rec in records.values())
    supplement = latest(directory(run), run, r["sample_sha256"], r["model"]["digest"]) if dotnet else None
    if supplement:
        from .field_review import recent
        parent = directory(run) / "supplements" / supplement["id"]
        supplement["field_reviews"] = recent(parent, parent / "events.jsonl")
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
        "search_attempts": attempts,
        "graph": graph,
        "cited_windows": cited_windows(records, graph, claims + rejected),
        "graph_origin": "terminal" if frozen_graph is not None else "reconstructed",
        "claims": claims,
        "rejected_claims": rejected,
        "transfer_evidence_claim_ids": analysis.get("transfer_evidence_claim_ids", []),
        "can_supplement": dotnet,
        "supplement": supplement,
        "yara": yara,
        "anchors": anchors,
        "questions": questions,
    }


def records_for(run):
    log = directory(run) / "events.jsonl"
    return source(run, (log.stat().st_size, log.stat().st_mtime_ns))[0]
