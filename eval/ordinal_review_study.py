"""Measure column review on identical historical claims and one fresh web investigation."""
import argparse
import json
from collections import Counter
from copy import deepcopy
from hashlib import sha256

from eval.transfer_live_audit import check
from eval.transfer_report_audit import require
from eval.web_report_quality import EVIDENCE, ROOT, read
from lab_web.cases import RUN
from stealer_agent import column_review
from stealer_agent.journal import Journal, canonical, dump_json, record_model_request, verify_journal
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient

PLAN = ROOT / "eval/adjudications/ordinal-review-protocol.json"
LABELS = PLAN.with_name("ordinal-review-claims.json")
PUBLIC = EVIDENCE / "ordinal-review-study.json"
TRIAL = ROOT / "private/ordinal-review" / "first"
CONFIG = ROOT / "config/host.investigation.example.json"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def journal(path):
    verify_journal(path)
    return list(map(json.loads, path.read_bytes().splitlines()))


def history():
    plan, labels = read(PLAN), read(LABELS)
    parent = ROOT / "runs" / plan["baseline"] / "events.jsonl"
    require(digest(parent) == plan["baseline_journal_sha256"] and labels["run"] == plan["baseline"],
            "Different registered parent")
    events = journal(parent)
    cards = {e["card_id"]: e["operations"] for e in events if e["event"] == "card_operation_context"}
    cases = {}
    current = None
    for e in events:
        if e["event"] == "card_claim_proposed":
            c = e["claim"]
            current = c["id"] if any(f["operation"] == "reader_ordinal_field" for f in cards[e["card_id"]]) else None
            if current:
                cases[current] = {"claim": c}
        elif current and e["event"] == "model_request" and e["phase"] == "card_review":
            require(json.loads(e["messages"][-1]["content"])["claim"] == cases[current]["claim"]["text"]
                    and sha256(canonical(e["messages"])).hexdigest() == e["messages_sha256"], "Different old request")
            cases[current]["request"] = e
        elif current and e["event"] == "card_claim_review":
            require(e["claim_id"] == current, "Different old decision")
            cases[current]["original"] = e["check"]["supported"]
            current = None
    require(list(cases) == plan["paired_claims"] and set(cases) == labels["claims"].keys(), "Changed cohort")
    for cid, case in cases.items():
        cited = {n for r in case["claim"]["evidence"] for n in range(r["line"], r["end_line"] + 1)}
        require(set(labels["claims"][cid]["lines"]) <= cited, "Reference lines outside the claim")
    return cases


def updated_request(entry):
    messages = deepcopy(entry["request"]["messages"])
    messages[0]["content"] += column_review.GUIDANCE + column_review.REVIEW
    return messages


def run_paired():
    cases = history()
    cfg, plan = read(CONFIG), read(PLAN)
    require(digest(CONFIG) == plan["config_sha256"] and
            all(digest(ROOT / name) == d for name, d in plan["source_sha256"].items()), "Different experiment code")
    client = OllamaClient(cfg)
    model = client.inspect()["digest"]
    require(model == read(EVIDENCE / f"web-{plan['baseline']}.json")["model_digest"], "Different model")
    log = Journal(TRIAL)
    log.append("start", plan=digest(PLAN), labels=digest(LABELS), model=model)
    for i, (cid, case) in enumerate(cases.items(), 1):
        free = available_memory_bytes()
        if free is not None and free < cfg.get("minimum_free_ram_mb", 256) * 1024**2:
            client.unload()
            log.append("interrupted", claim=cid, reason="memory_floor")
            raise RuntimeError("Insufficient memory for paired trial")
        msgs = updated_request(case)
        record_model_request(log, step=i, messages=msgs, schema=column_review.SCHEMA,
                             evidence=case["request"]["evidence"], phase="card_review", claim=cid)
        answer, usage = client.chat(msgs, column_review.SCHEMA)
        log.append("decision", claim=cid, assessment=answer, metrics=usage)
    log.append("finished", cases=len(cases))


def paired_rows():
    cases, labels = history(), read(LABELS)["claims"]
    events = journal(TRIAL / "events.jsonl")
    plan = read(PLAN)
    require(events[0]["plan"] == digest(PLAN) and events[0]["labels"] == digest(LABELS)
            and events[0]["model"] == read(EVIDENCE / f"web-{plan['baseline']}.json")["model_digest"]
            and events[-1]["event"] == "finished" and len(events) == 2 * len(cases) + 2, "Incomplete paired trace")
    rows = []
    for i, (cid, case) in enumerate(cases.items()):
        req, resp = events[1 + 2*i : 3 + 2*i]
        require(req["claim"] == resp["claim"] == cid and req["messages"] == updated_request(case)
                and req["schema"] == column_review.SCHEMA and req["evidence"] == case["request"]["evidence"],
                "Different paired model inputs")
        answer = resp["assessment"]
        ruling = column_review.decision(case["claim"]["text"], answer)
        rows.append({"id": cid, "reference": labels[cid]["supported"], "before": case["original"],
                     "after": ruling == "ordinary_review" and answer.get("supported") is True,
                     "ruling": ruling, "claim_sha256": sha256(canonical(case["claim"])).hexdigest(),
                     "request_sha256": req["messages_sha256"], "lines": labels[cid]["lines"]})
    return rows


def live_arm(run):
    receipt = read(EVIDENCE / f"web-{run}.json")
    result = {"run": run, "status": receipt["status"], "journal": receipt["journal_sha256"],
              "score": None, "claims": receipt["accepted_claims"], "verdict": receipt["verdict"],
              "tool_calls": receipt["metrics"]["tool_calls"], "seconds": receipt["metrics"]["elapsed_s"]}
    if receipt["status"].startswith("completed"):
        grade = read(EVIDENCE / f"transfer-live-{run}.json")
        require(not grade["unmatched"] and grade["journal_sha256"] == result["journal"], "Incomplete live grade")
        result["score"] = grade["graded_score"]
    return result


def claim_quality(run, decisions):
    """Count each emitted sentence once; grade distinct frozen reference units separately."""
    rows = []
    for c in decisions:
        if not c["retained"]:
            continue
        atoms = c["atoms"]
        require(atoms and c["citation_count"] > 0, "Missing source audit or citation")
        rows.append({"claim": c["id"], "signature": c["signature"], "citations": c["citation_count"],
                     "labels": [label for _, label in atoms]})
    require(len(rows) == live_arm(run)["claims"], "Incomplete sentence count")
    return rows


def sentence_rates(rows):
    count = len(rows)
    labels = [r["labels"] for r in rows]
    require(len({r["claim"] for r in rows}) == count and
            all(ls and set(ls) <= {"correct", "incorrect", "unsupported"} for ls in labels), "Invalid sentence grade")
    correct = sum(set(ls) == {"correct"} for ls in labels)
    unsupported = sum("unsupported" in ls for ls in labels)
    incorrect = sum("incorrect" in ls and "unsupported" not in ls for ls in labels)
    cited = sum(r["citations"] > 0 for r in rows)
    return {"total": count, "correct": correct, "incorrect": incorrect, "unsupported": unsupported,
            "grounded": cited, "precision": correct / count if count else None,
            "unsupported_rate": unsupported / count if count else None, "citation_rate": cited / count if count else None}


def build(run):
    require(RUN.fullmatch(run), "Expected a run ID")
    plan = read(PLAN)
    trace = journal(ROOT / "runs" / run / "events.jsonl")
    start = trace[0]
    require(start["sample"] == plan["sample"] and start["timestamp"] > plan["registered_at"], "Wrong live attempt")
    for path in (ROOT / "runs").glob("*/events.jsonl"):
        if RUN.fullmatch(path.parent.name) and path.parent.name < run:
            with path.open("rb") as stream:
                old = json.loads(stream.readline())
            require(old.get("sample") != plan["sample"] or old["timestamp"] < plan["registered_at"],
                    "An earlier attempt was omitted")
    source = next(e["files"] for e in trace if e["event"] == "source_version")
    require(all(source[k] == v for k, v in plan["source_sha256"].items()), "Different live core")
    parents = [plan["baseline"], run]
    arms = [live_arm(r) for r in parents]
    sentences = {}
    for arm in arms:
        if arm["score"] is not None:
            grade = read(EVIDENCE / f"transfer-live-{arm['run']}.json")
            checked = check(arm["run"], grade["interaction"], include_decisions=True)
            sentences[arm["run"]] = claim_quality(arm["run"], checked.pop("decisions"))
            require(checked == grade, "Different private grade")
    checks = [e for e in trace if e["event"] == "column_review"]
    claims = {e["claim"]["id"]: e["claim"] for e in trace if e["event"] == "card_claim_proposed"}
    kept = {c["id"] for c in trace[-1]["result"]["analysis"]["claims"]}
    for e in checks:
        require(e["method"] == column_review.VERSION and
                e["ruling"] == column_review.decision(claims[e["claim_id"]]["text"], e["assessment"])
                and (e["ruling"] == "ordinary_review" or e["claim_id"] not in kept), "Invalid ordinal review")
    return {"plan": digest(PLAN), "labels": digest(LABELS), "paired_journal": digest(TRIAL / "events.jsonl"),
            "paired": paired_rows(), "arms": arms, "sentences": sentences,
            "live_checks": [{"id": e["claim_id"], "card": e["card_id"], "basis": e["assessment"].get("column_basis"),
                             "ruling": e["ruling"], "retained": e["claim_id"] in kept} for e in checks]}


def published():
    data, plan, labels = read(PUBLIC), read(PLAN), read(LABELS)["claims"]
    before, after = data["arms"]
    require(data["plan"] == digest(PLAN) and data["labels"] == digest(LABELS)
            and before["run"] == plan["baseline"] and after["run"] > before["run"]
            and data["arms"] == [live_arm(before["run"]), live_arm(after["run"])], "Different public grade")
    parent, child = [read(EVIDENCE / f"web-{arm['run']}.json") for arm in data["arms"]]
    require(all(parent[k] == child[k] for k in ("sha256", "model_digest", "config_sha256_excluding_sample"))
            and parent["source_manifest_sha256"] != child["source_manifest_sha256"], "Incomparable revisions")
    require([r["id"] for r in data["paired"]] == plan["paired_claims"] and
            all((r["reference"], r["lines"]) == (labels[r["id"]]["supported"], labels[r["id"]]["lines"])
                for r in data["paired"]), "Different reference claims")
    require(set(data["sentences"]) == {a["run"] for a in data["arms"] if a["score"] is not None}
            and all(len(rows) == live_arm(run)["claims"] for run, rows in data["sentences"].items()),
            "Published sentence count differs")
    counts = {arm: dict(Counter(("keep" if r[arm] else "reject") + ("_right" if r["reference"] else "_wrong")
                                for r in data["paired"])) for arm in ("before", "after")}
    return {**data, "paired_counts": counts, "sentence_rates": {
        run: sentence_rates(rows) for run, rows in data["sentences"].items()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--paired", action="store_true")
    parser.add_argument("--write", metavar="RUN")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if args.paired:
        run_paired()
    elif args.write:
        dump_json(PUBLIC, build(args.write))
    if PUBLIC.exists() or not args.paired:
        result = published()
        if args.replay:
            require(read(PUBLIC) == build(result["arms"][1]["run"]), "Private replay differs")
        print(result["paired_counts"], result["arms"][1]["score"])
