"""Evaluate both .NET formats of column arguments against real full reports."""
import argparse
from collections import Counter
from hashlib import sha256

from eval.transfer_live_audit import check
from eval.transfer_report_audit import require
from eval.web_report_exposure import events, reconstruct, request_windows, required_rows, source_id
from eval.web_report_quality import EVIDENCE, ROOT, read
from lab_web.cases import RUN
from stealer_agent.journal import dump_json
from stealer_agent.operation_assertions import render
from stealer_agent.operation_context import valid_operations
from scripts.report_experiment_receipt import config_digest

PLAN = ROOT / "eval/adjudications/table-access-protocol.json"
PUBLIC = EVIDENCE / "table-access-comparison.json"
READS = {"reader_named_field", "reader_ordinal_field"}
STATES = {"retained", "missing_source", "visible_in_one_request", "split_source", "not_presented"}


def file_hash(p):
    return sha256(p.read_bytes()).hexdigest()


def extract(run, profile, before):
    journal = events(run)
    receipt = read(EVIDENCE / f"web-{run}.json")
    log = ROOT / "runs" / run / "events.jsonl"
    require(file_hash(log) == receipt["journal_sha256"] and journal[-1]["event"] == "run_finished"
            and journal[-1]["result"] == read(log.parent / "report.private.json"), "Different terminal journal")
    if not before:
        manifest = next(e for e in journal if e["event"] == "source_version")
        require(manifest["files"]["vm_tools/table_access.py"] == read(PLAN)["parser_sha256"],
                "Different reader under test")
    record = reconstruct(journal)
    if not receipt["status"].startswith("completed") and not any(
        e["event"] == "observation" and e["model_visible"].get("tool") == "decompile_dotnet"
        and e["model_visible"].get("status") == "ok" for e in journal
    ):
        return {"run": run, "journal_sha256": receipt["journal_sha256"],
                "states": {u["id"]: "missing_source" for u in profile["units"]}, "facts": []}
    eid = source_id(profile, journal)
    source = record[eid]
    lines = source["line_map"]
    windows = request_windows(journal, eid, lines, include_flow=True)
    visible = set().union(*windows)
    matched = set()
    if receipt["status"].startswith("completed"):
        grade = read(EVIDENCE / f"transfer-live-{run}.json")
        replay = check(run, grade["interaction"], include_coverage=True)
        matched = set(replay.pop("covered_units"))
        require(grade == replay and not grade["unmatched"], "Private grade differs")
    states = {}
    for unit in profile["units"]:
        required = required_rows(unit, source, profile)
        if unit["id"] in matched:
            state = "retained"
        elif required - lines.keys():
            state = "missing_source"
        elif any(required <= window for window in windows):
            state = "visible_in_one_request"
        elif required <= visible:
            state = "split_source"
        else:
            state = "not_presented"
        states[unit["id"]] = state
    facts = {f["fact_id"]: f for f in valid_operations(source) if f["operation"] in READS}
    reviews = {e["fact_id"]: e for e in journal if e["event"] == "operation_review_decision"}
    terminal = {c["id"]: c for c in journal[-1]["result"]["analysis"]["claims"]}
    table = []
    for fid, fact in facts.items():
        decision = reviews.get(fid)
        claim_id = decision.get("claim_id") if decision and decision["selected"] else None
        ranges = [[r["line"], r["end_line"]] for r in fact["ranges"]]
        if claim_id in terminal and receipt["status"].startswith("completed"):
            claim = terminal[claim_id]
            require(claim["text"] == render(fact) and ranges == [[r["line"], r["end_line"]] for r in claim["evidence"]]
                    and all(r["evidence_id"] == eid and r["quote"] == "\n".join(lines[n] for n in range(r["line"], r["end_line"]+1))
                            for r in claim["evidence"]), "Unbound terminal reader assertion")
        table.append({"kind": fact["operation"], "fact": fid, "ranges": ranges, "reviewed": decision is not None,
                      "claim": claim_id if claim_id in terminal else None})
    return {"run": run, "journal_sha256": receipt["journal_sha256"], "states": states, "facts": table}


def project(cases):
    plan = read(PLAN)
    config = ROOT / "config/host.investigation.example.json"
    require(file_hash(config) == plan["config_sha256"], "Different registered configuration")
    logged_settings = {k: v for k, v in read(config).items() if "token" not in k}
    expected_config = config_digest({**logged_settings, "live_progress": True, "require_course_model": True,
                                     "evidence_kind": "real-public-malware-local-slm-vm"})
    require(len(cases) == len(plan["samples"]) == 2, "Both planned samples required")
    out = []
    for case, declared in zip(cases, plan["samples"], strict=True):
        path = ROOT / "eval/reference_units" / declared["profile"]
        profile = read(path)
        require(file_hash(path) == declared["profile_sha256"] and case["before"]["run"] == declared["before"],
                "Different profile or baseline")
        arms = {}
        for key in ("before", "after"):
            arm = case[key]
            live = read(EVIDENCE / f"web-{arm['run']}.json")
            if key == "before":
                base = live
            require(RUN.fullmatch(arm["run"]) and arm["journal_sha256"] == live["journal_sha256"]
                    and live["config_sha256_excluding_sample"] == expected_config
                    and live["sample"] == declared["sample"] and live["sha256"] == profile["sample_sha256"]
                    and all(live[k] == base[k] for k in ("config_sha256_excluding_sample", "model_digest"))
                    and set(arm["states"]) == {u["id"] for u in profile["units"]}
                    and set(arm["states"].values()) <= STATES, "Different run, sample, config or coverage")
            facts = arm["facts"]
            require(len({f["fact"] for f in facts}) == len(facts)
                    and all(f["kind"] in READS and len(f["ranges"]) >= 1 and
                            all(0 < start <= end for start, end in f["ranges"]) and
                            (f["claim"] is None or f["reviewed"]) for f in facts), "Malformed reader facts")
            counts = dict(Counter(arm["states"].values()))
            score = None
            if live["status"].startswith("completed"):
                grade = read(EVIDENCE / f"transfer-live-{arm['run']}.json")
                score = grade["graded_score"]
                require(not grade["unmatched"] and grade["journal_sha256"] == live["journal_sha256"]
                        and grade["source_profile_sha256"] == file_hash(path)
                        and counts.get("retained", 0) == score["correct"]
                        and len(profile["units"]) == score["correct"] + score["missed"], "Different report score")
            else:
                require(not counts.get("retained", 0), "Incomplete report cannot claim coverage")
            arms[key] = {"run": arm["run"], "status": live["status"], "score": score, "verdict": live["verdict"],
                         "states": counts, "facts": facts, "tool_calls": live["metrics"]["tool_calls"],
                         "model_calls": live["metrics"]["model_calls"], "seconds": live["metrics"]["elapsed_s"],
                         "core": live["source_manifest_sha256"]}
        old, new = case["before"]["states"], case["after"]["states"]
        out.append({"sample": declared["sample"], **arms,
                    "gained": sorted(i for i in new if new[i] == "retained" and old[i] != "retained"),
                    "lost": sorted(i for i in new if old[i] == "retained" and new[i] != "retained")})
    require(out[0]["after"]["core"] == out[1]["after"]["core"], "Different candidate revisions")
    require(out[0]["after"]["run"] < out[1]["after"]["run"]
            and all(r["before"]["run"] < r["after"]["run"] for r in out), "Run IDs out of order")
    return out


def build(ids):
    from json import loads
    plan = read(PLAN)
    first = []
    for path in sorted((ROOT / "runs").glob("*/events.jsonl")):
        if RUN.fullmatch(path.parent.name):
            with path.open("rb") as stream:
                event = loads(stream.readline())
            if event["timestamp"] >= plan["recorded_at"] and event.get("sample") in {s["sample"] for s in plan["samples"]}:
                first.append(path.parent.name)
    require(ids == first[:2], "Expected the first two specified attempts")
    cases = []
    for sample, run in zip(plan["samples"], ids, strict=True):
        profile = read(ROOT / "eval/reference_units" / sample["profile"])
        cases.append({"before": extract(sample["before"], profile, True), "after": extract(run, profile, False)})
    return {"plan_sha256": file_hash(PLAN), "cases": cases, "results": project(cases)}


def published():
    data = read(PUBLIC)
    require(data["plan_sha256"] == file_hash(PLAN) and data["results"] == project(data["cases"]),
            "Published comparison differs")
    return data["results"]


METHOD_PLAN = ROOT / "eval/adjudications/intact-method-protocol.json"
METHOD_RESULT = EVIDENCE / "intact-method-check.json"


def verify_screens(clicks, arm, live):
    require(clicks["run"] == arm["run"] and not (clicks["errors"] or clicks["external"]),
            "Browser interaction failed")
    rows = {s["id"]: s for s in clicks["sites"]}
    require(len(rows) == len(clicks["sites"]) == len(arm["facts"]), "Different displayed site count")
    for fact in arm["facts"]:
        site = rows[fact["fact"]]
        require(site["ordinal"] == (fact["kind"] == "reader_ordinal_field") and site["claim"] == fact["claim"]
                and [r[:2] for r in site["spans"]] == fact["ranges"]
                and all(r[2] == live for r in site["spans"]), "Different displayed citations")
    count = sum(len(f["ranges"]) for f in arm["facts"])
    require(clicks["screens"] == [{"width": w, "sites": len(rows), "references": count} for w in (390, 1360)],
            "Incomplete mobile or desktop check")


def method_result(run=None, *, replay=False):
    plan = read(METHOD_PLAN)
    paired = published()
    profile_path = ROOT / "eval/reference_units/mercurial.atomic-v1.json"
    profile = read(profile_path)
    before = paired[1]["after"]
    require(before["run"] == plan["baseline"], "Different baseline for scoped retry")
    if replay:
        saved = read(METHOD_RESULT)
        run = saved["attempt"]["run"]
    if run:
        journal = events(run)
        require(RUN.fullmatch(run) and journal[0]["timestamp"] > plan["registered_at"] and
                journal[0]["sample"] == plan["sample"], "Not a subsequent planned case")
        from json import loads
        for path in sorted((ROOT / "runs").glob("*/events.jsonl")):
            if not RUN.fullmatch(path.parent.name) or path.parent.name >= run:
                continue
            with path.open("rb") as stream:
                start = loads(stream.readline())
            require(start.get("sample") != plan["sample"] or start["timestamp"] < plan["registered_at"],
                    "Earlier attempt omitted")
        manifest = next(e["files"] for e in journal if e["event"] == "source_version")
        require(all(manifest[k] == v for k, v in plan["source_sha256"].items()), "Different scoped parser")
        data = {"plan_sha256": file_hash(METHOD_PLAN), "attempt": extract(run, profile, False),
                "clicks": [read(ROOT / "evidence/local" / f"reader-web-{rid}.json")
                           for rid in [paired[0]["after"]["run"], before["run"], run]]}
    else:
        data = read(METHOD_RESULT)
    attempt = data["attempt"]
    live = read(EVIDENCE / f"web-{attempt['run']}.json")
    old = read(EVIDENCE / f"web-{before['run']}.json")
    require(data["plan_sha256"] == file_hash(METHOD_PLAN) and live["sample"] == plan["sample"]
            and attempt["journal_sha256"] == live["journal_sha256"] and live["run"] > old["run"]
            and all(live[k] == old[k] for k in ("sha256", "model_digest", "config_sha256_excluding_sample"))
            and live["source_manifest_sha256"] != old["source_manifest_sha256"], "Different scoped experiment")
    require(set(attempt["states"]) == {u["id"] for u in profile["units"]}
            and set(attempt["states"].values()) <= STATES
            and all(f["kind"] in READS and (f["claim"] is None or f["reviewed"]) for f in attempt["facts"]),
            "Incomplete reference grid or unreviewed claim")
    sources = [read(ROOT / "eval/reference_units" / x["profile"]) for x in read(PLAN)["samples"]]
    arms = [paired[0]["after"], before, attempt]
    for clicks, arm, src in zip(data["clicks"], arms, [*sources, profile], strict=True):
        digest, = {r["output_sha256"] for r in src["source_references"] if isinstance(r, dict) and "output_sha256" in r}
        verify_screens(clicks, arm, digest)
    grade = read(EVIDENCE / f"transfer-live-{live['run']}.json") if live["status"].startswith("completed") else None
    if grade:
        require(grade["journal_sha256"] == live["journal_sha256"] and not grade["unmatched"] and
                grade["source_profile_sha256"] == file_hash(profile_path) and
                sum(state == "retained" for state in attempt["states"].values()) == grade["graded_score"]["correct"],
                "Scope or grade differs from the source profile")
    if replay:
        require(data == saved, "Scoped browser or journal replay differs")
    elif run:
        dump_json(METHOD_RESULT, data)
    return {"run": live["run"], "status": live["status"], "verdict": live["verdict"],
            "facts": attempt["facts"], "score": grade["graded_score"] if grade else None,
            "states": dict(Counter(attempt["states"].values())), "tool_calls": live["metrics"]["tool_calls"],
            "model_calls": live["metrics"]["model_calls"], "seconds": live["metrics"]["elapsed_s"]}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--write", nargs=2, metavar="RUN")
    cli.add_argument("--replay", action="store_true")
    cli.add_argument("--method-run")
    args = cli.parse_args()
    if args.write:
        dump_json(PUBLIC, build(args.write))
    results = published()
    if args.method_run or METHOD_RESULT.is_file():
        retry = method_result(args.method_run, replay=args.replay and not args.method_run)
        print("Scoped method check", retry["run"], retry["score"], len(retry["facts"]), "sites")
    if args.replay:
        require(build([r["after"]["run"] for r in results]) == read(PUBLIC), "Private replay differs")
    for r in results:
        print(r["sample"], r["before"]["score"], "->", r["after"]["score"], "gained", r["gained"], "lost", r["lost"])
