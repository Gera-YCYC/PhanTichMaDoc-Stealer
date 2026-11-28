"""Reproduce the bounded path check on original VM records and web journals."""

import argparse
from hashlib import sha256
import json
import re
import subprocess

from eval.web_report_exposure import source_id
from eval.transfer_live_audit import check as grade_report
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, read
from lab_web.cases import records_for
from scripts.sync_vm import DEST, SSH
from stealer_agent.journal import dump_json, verify_journal
from stealer_agent.staging_evidence import checked_path

OLD = "20261128T053257_fbd5c41a"
NEW = "20261128T071542_c577c28e"
REPEAT = "20261128T073934_730537f9"
PUBLIC = EVIDENCE / "staging-path-python.json"
# Source-reviewed coordinates for this development family only.
SITES = {
    "source_call": 299,
    "writer_call": 308,
    "writer": 116,
    "open": 123,
    "write": 124,
    "archive": 279,
    "archive_call": 315,
    "root": 25,
    "domain": 27,
    "select": 262,
    "selection_call": 292,
    "iteration": 294,
    "archive_helper": 276,
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def journal(path):
    verify_journal(path)
    return list(map(json.loads, path.read_bytes().splitlines()))


def fingerprint(path):
    return sha256(path.read_bytes()).hexdigest()


# Operates on an already extracted, immutable feature record in the VM.
# The host receives coordinates and digests only.
REPLAY = r"""
import json,sys,re,hashlib
from pathlib import Path
from vm_tools.operation_facts import extract_operations
from vm_tools.staging_link import find_witness
from stealer_agent.journal import canonical
eid,digest,output,windows=json.loads(sys.stdin.readline())
if not re.fullmatch(r"ev_[a-f0-9]{16}",eid):
    raise ValueError("Bad VM record")
r=json.loads((Path("/opt/stealer-lab/private/tool-evidence")/(eid+".json")).read_bytes())
if (eid,digest,output)!=(r["evidence_id"],r["sample_sha256"],r["output_sha256"]) or hashlib.sha256(canonical(r["lines"])).hexdigest()!=output:
    raise ValueError("Evidence mismatch")
facts=extract_operations(r)["facts"]
result=[find_witness(r,facts,window) for window in windows]
print(json.dumps({"method":hashlib.sha256(Path("vm_tools/staging_link.py").read_bytes()).hexdigest(),"results":result}))
"""


def sample(run, with_vm, saved):
    folder = ROOT / "runs" / run
    path = folder / "events.jsonl"
    events = journal(path)
    report = read(folder / "report.private.json")
    require(
        events[-1]["event"] == "run_finished" and events[-1]["result"] == report,
        "Incomplete terminal run",
    )
    digest = report["sample_sha256"]
    eid = source_id(read(PROFILE), events)
    record = records_for(run)[eid]
    steps = {
        e["step"]
        for e in events
        if e["event"] == "hypothesis_open" and e["edge"] == "write-archive"
    }
    queries = []
    proofs = []
    dispatched = {
        e["step"]: e["arguments"] for e in events if e["event"] == "action_dispatched"
    }
    for e in events:
        if e["event"] != "observation" or e.get("step") not in steps:
            continue
        raw = e["raw"]
        if raw["evidence_id"] != eid:
            continue
        call = dispatched[e["step"]]
        window = sorted({n for g in raw.get("search_groups", []) for n in g["lines"]})
        queries.append(
            {
                "step": e["step"],
                "window": window,
                "asked": call.get("verify_staging", False),
                "hits": raw["hit_count"],
                "returned": "staging_link" in raw,
            }
        )
        proofs.append(raw.get("staging_link"))
    require(queries, "No real investigation steps")
    if with_vm:
        import shlex

        command = (
            "cd /opt/stealer-lab && sudo -u analyst env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps python3 -c "
            + shlex.quote(REPLAY)
        )
        proc = subprocess.run(
            ["ssh", *SSH, DEST, command],
            input=json.dumps(
                [eid, digest, record["output_sha256"], [q["window"] for q in queries]]
            ),
            encoding="utf8",
            capture_output=True,
            check=True,
            timeout=60,
        )
        measured = json.loads(proc.stdout)
        require(
            measured["method"] == fingerprint(ROOT / "vm_tools/staging_link.py"),
            "Guest uses a different parser",
        )
        decisions = []
        for q, found, recorded in zip(
            queries, measured["results"], proofs, strict=True
        ):
            if found:
                require(
                    found["roles"] == SITES and found["component_count"] == 16,
                    "Different source witness",
                )
            if recorded or q["asked"]:
                require(found == recorded, "Changed VM result on an original request")
            decisions.append(found["proof_id"] if found else None)
    else:
        decisions = saved["probe_ids"]
        for q, token, recorded in zip(queries, decisions, proofs, strict=True):
            if q["asked"] or recorded:
                require(
                    token == (recorded or {}).get("proof_id"),
                    "Different proof in the original journal",
                )
    edge = next(
        x for x in report["investigation"]["edges"] if x["id"] == "write-archive"
    )
    final = checked_path(record, digest)
    require(
        final == edge.get("path_check") and edge["status"] == "partial",
        "Stored evidence differs from terminal graph",
    )
    if run == NEW:
        require(final and final["roles"] == SITES, "Missing verified path")
    else:
        require(not final, "Historical graph has changed")
    new_claims = [
        e["claim_id"]
        for e in events
        if e["event"] == "flow_review_decision" and e["route"] == "result_to_writer"
    ]
    kept = {c["id"] for c in report["analysis"]["claims"]}
    return {
        "run": run,
        "journal_sha256": fingerprint(path),
        "model_digest": report["model"]["digest"],
        "sample_sha256": digest,
        "output_sha256": record["output_sha256"],
        "eid": eid,
        "vm_parser_at_run": next(
            e["files"]["vm_tools/staging_link.py"]
            for e in events
            if e["event"] == "source_version"
        )
        if run == NEW
        else None,
        "steps": queries,
        "probe_ids": decisions,
        "final_path_verified": bool(final),
        "source_line_count": sum(ref["end"] - ref["line"] + 1 for ref in final["refs"])
        if final
        else 0,
        "possible_names": final["component_count"] if final else None,
        "overall_link": edge["status"],
        "verdict": report["analysis"]["verdict"],
        "new_candidates": new_claims,
        "new_accepted": [cid for cid in new_claims if cid in kept],
    }


def inspect_ui(new, clicks):
    folder = ROOT / "runs" / NEW
    require(
        re.fullmatch(r"q_[a-f0-9]{12}", clicks["question_journal"]), "Unknown question"
    )
    p = folder / "questions" / clicks["question_journal"] / "events.jsonl"
    events = journal(p)
    answer = events[-1]["answer"]
    (call,) = [e for e in events if e["event"] == "action_dispatched"]
    check = checked_path(records_for(NEW)[new["eid"]], new["sample_sha256"])
    expected = [[r["line"], r["end"], new["output_sha256"]] for r in check["refs"]]
    require(
        clicks["run"] == events[0]["run"] == NEW
        and clicks["spans"] == expected
        and not clicks["external"]
        and not clicks["errors"]
        and clicks["width"] == 390
        and events[-1]["event"] == "answered"
        and answer["topic"] == clicks["topic"] == "write-archive"
        and events[0]["model"] == new["model_digest"]
        and events[0]["sample_sha256"] == new["sample_sha256"]
        and answer["refs"] == check["refs"]
        and clicks["answer_refs"] == len(expected)
        and call["action"] == "search_evidence"
        and call["arguments"]["evidence_id"] == new["eid"]
        and call["arguments"]["query"]
        in {"remove(", "unlink(", "rmtree(", "replace(", "rename("}
        and answer["search"]["status"] == "ok"
        and clicks["search_hits"] == answer["search"]["hit_count"]
        and "Chưa chứng minh" in answer["text"],
        "Browser or QA proof differs",
    )
    return {
        "clicks": clicks,
        "question_sha256": fingerprint(p),
        "query": call["arguments"]["query"],
    }


def verify_public(data):
    require(data["repeat_run"] == REPEAT, "Wrong end-to-end repeat")
    old, new = data["runs"]
    for row, expected in zip([old, new], [OLD, NEW], strict=True):
        full = read(EVIDENCE / f"web-{expected}.json")
        require(
            row["run"] == expected
            and row["journal_sha256"] == full["journal_sha256"]
            and row["sample_sha256"] == full["sha256"]
            and row["model_digest"] == full["model_digest"]
            and row["verdict"] == full["verdict"]
            and row["overall_link"] == "partial"
            and len(row["steps"]) == len(row["probe_ids"]),
            "Unbound public receipt",
        )
        dispatches = [
            g["step"]
            for g in full["gaps"]
            if g["edge"] == "write-archive" and "hit_count" not in g
        ]
        require(
            [q["step"] for q in row["steps"]] == dispatches, "Different search steps"
        )
        for q, token in zip(row["steps"], row["probe_ids"], strict=True):
            require(
                token is None or re.fullmatch(r"stage_[0-9a-f]{16}", token),
                "Invalid proof ID",
            )
            require(
                q["window"] == sorted(set(q["window"]))
                and all(type(n) is int and n > 0 for n in q["window"]),
                "Invalid search window",
            )
            if q["asked"]:
                require(
                    q["returned"] == bool(token),
                    "Actual VM dispatch differs from later check",
                )
    clicks = data["ui"]["clicks"]
    before, after = [set(row["covered_units"]) for row in (old, new)]
    require(
        before - after == {"PY24-A09", "PY24-A26"} and not after - before,
        "Different coverage delta",
    )
    for row in (old, new):
        grade = read(EVIDENCE / f"transfer-live-{row['run']}.json")
        require(
            grade["journal_sha256"] == row["journal_sha256"]
            and not grade["unmatched"]
            and len(set(row["covered_units"]))
            == len(row["covered_units"])
            == grade["graded_score"]["correct"]
            and set(row["covered_units"])
            <= {unit["id"] for unit in read(PROFILE)["units"]},
            "Different graded report",
        )
    (entry,) = [q for q in full["questions"] if q["id"] == clicks["question_journal"]]
    spans = clicks["spans"]
    lines = [n for start, end, digest in spans for n in range(start, end + 1)]
    require(
        clicks["run"] == NEW
        and clicks["width"] == 390
        and not clicks["errors"]
        and not clicks["external"]
        and entry["journal_sha256"] == data["ui"]["question_sha256"]
        and entry["status"] == "answered"
        and entry["search_errors"] == 0
        and entry["search_calls"] == 1
        and entry["topic"] == clicks["topic"] == "write-archive"
        and entry["search_hits"] == [clicks["search_hits"]]
        and entry["source_refs"] == clicks["answer_refs"] == len(spans)
        and all(
            0 < start <= end and digest == new["output_sha256"]
            for start, end, digest in spans
        )
        and set(SITES.values()) <= set(lines)
        and lines == sorted(set(lines))
        and len(lines) == new["source_line_count"] == 38
        and new["possible_names"] == 16
        and not old["source_line_count"]
        and old["possible_names"] is None,
        "Different public question or excerpts",
    )
    require(
        not old["final_path_verified"]
        and new["final_path_verified"]
        and old["sample_sha256"] == new["sample_sha256"]
        and old["model_digest"] == new["model_digest"]
        and data["ui"]["clicks"]["spans"]
        and any(q["returned"] for q in new["steps"])
        and data["parser_sha256"] == fingerprint(ROOT / "vm_tools/staging_link.py"),
        "Incomplete comparison",
    )


def verify_repeat():
    full = read(EVIDENCE / f"web-{REPEAT}.json")
    grade = read(EVIDENCE / f"transfer-live-{REPEAT}.json")
    (check,) = [
        e["path_check"]
        for e in full["terminal_edges"]
        if e["id"] == "write-archive" and e["status"] == "partial"
    ]
    browser = full["staging_browser"]
    (question,) = [q for q in full["questions"] if q["id"] == browser["question"]]
    opened = browser["search_spans_opened"]
    (digest,) = {w[2] for w in check["spans"]}
    require(
        full["run"] == grade["run"] == REPEAT
        and full["journal_sha256"] == grade["journal_sha256"]
        and full["current_logic_matches_run"]
        and full["displayed_edges_match_terminal"]
        and full["staging_parser_sha256"]
        == fingerprint(ROOT / "vm_tools/staging_link.py")
        and check["relation"] == "writer_path_beneath_archive_input"
        and check["possible_names"] == 16
        and check["unresolved"] == "file_presence_at_archive_time"
        and len(check["spans"]) == browser["graph_spans_opened"] == 13
        and sum(hi - lo + 1 for lo, hi, _ in check["spans"]) == 38
        and len(opened) == 2
        and all(lo == hi and sha == digest for lo, hi, sha in opened)
        and question["journal_sha256"] == browser["question_journal_sha256"]
        and question["opened_anchors"] == [[lo for lo, _, _ in opened]]
        and question["search_hits"] == [8]
        and question["source_refs"] == 13
        and question["search_errors"] == 0
        and question["search_calls"] == 1
        and grade["graded_score"]["correct"] == 20
        and grade["graded_score"]["missed"] == 16
        and not grade["unmatched"],
        "Incomplete live repeat",
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--replay",
        action="store_true",
        help="Verify private journals and browser evidence",
    )
    p.add_argument(
        "--vm",
        action="store_true",
        help="Recompute each recorded search window inside the VM",
    )
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    if args.write and not args.vm:
        p.error("--write requires --vm")
    saved = {} if args.write else read(PUBLIC)
    data = saved
    if args.replay or args.vm:
        runs = [
            sample(r, args.vm, {} if args.write else saved["runs"][i])
            for i, r in enumerate((OLD, NEW))
        ]
        for row in runs:
            previous = read(EVIDENCE / f"transfer-live-{row['run']}.json")
            evaluated = grade_report(
                row["run"], previous["interaction"], include_coverage=True
            )
            row["covered_units"] = evaluated.pop("covered_units")
            require(
                evaluated == previous, "Private scores differ from published grades"
            )
        clicks = read(ROOT / "evidence/local" / f"staging-{NEW}.json")
        data = {
            "repeat_run": REPEAT,
            "parser_sha256": fingerprint(ROOT / "vm_tools/staging_link.py"),
            "runs": runs,
            "ui": inspect_ui(runs[1], clicks),
        }
        require(args.write or data == saved, "Different private replay")
    verify_public(data)
    verify_repeat()
    if args.write:
        dump_json(PUBLIC, data)
    for r in data["runs"]:
        print(
            r["run"],
            "actual verified:",
            r["final_path_verified"],
            "matching original windows:",
            sum(map(bool, r["probe_ids"])),
            "/",
            len(r["steps"]),
        )
