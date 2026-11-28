"""Replay the origin check on the four pre-labeled link probes and a subsequent Python diagnosis."""
import argparse

from eval.role_line_study import PUBLIC as ROLE_DATA, file_hash, published, replay_screen
from eval.ordinal_review_study import journal
from eval.verdict_trial import EVIDENCE, ROOT, read
from lab_web.cases import records_for
from stealer_agent.journal import dump_json
from stealer_agent.link_source import source_read
from stealer_agent.role_evidence import LINK
from stealer_agent.send_recovery import recover
from stealer_agent.verdict_support import enforce_stealer_support

OUT = EVIDENCE / "link-source-check.json"
PYTHON_RUN = "20261128T124815_dca6f7b8"
STOPPED_RUN = "20261128T130106_348c46bd"
RETRY_RUN = "20261128T130249_0fdc121a"


def result(run, checks, decision, scope):
    receipt = read(EVIDENCE / f"web-{run}.json")
    before = decision["status"] == "supported_by_review"
    found = source_read(decision, checks, records_for(run), receipt["sha256"]) if before else None
    return {"run":run, "journal":receipt["journal_sha256"], "claim":decision["claim"], "scope":scope,
            "original_status":decision["status"], "witnesses":decision["witnesses"],
            "read":found, "after":bool(before and found)}


def replay():
    rows = published()["rows"]
    output = []
    for row in rows:
        if row["role"] == LINK:
            same = [r for r in rows if r["run"] == row["run"]]
            output.append(result(row["run"], same, row, "fixed_negative"))
    report = read(ROOT / "runs" / PYTHON_RUN / "report.private.json")
    checks = report["analysis"]["role_checks"]
    row, = (r for r in checks if r["role"] == LINK and r["claim"] == "C2")
    output.append(result(PYTHON_RUN, checks, row, "development_diagnosis"))
    return output


def check(data):
    original = [r for r in read(ROLE_DATA)["rows"] if r["role"] == LINK]
    if any(r["expected"] for r in original):
        raise ValueError("The fixed control set changed")
    source = read(EVIDENCE / f"web-{PYTHON_RUN}.json")
    diagnosis, = (r for r in source["role_evidence_checks"] if r["role"] == LINK and r["claim"] == "C2")
    for i, (current, row) in enumerate(zip(data, [*original, {**diagnosis,"run":PYTHON_RUN}], strict=True)):
        if (current["run"] != row["run"] or current["claim"] != row["claim"]
                or current["journal"] != read(EVIDENCE / f"web-{row['run']}.json")["journal_sha256"]
                or current["scope"] != ("fixed_negative" if i < len(original) else "development_diagnosis")
                or current["witnesses"] != row["witnesses"] or current["original_status"] != row["status"]
                or current["after"] != bool(row["status"] == "supported_by_review" and current["read"])):
            raise ValueError("Different link assessment or source")
    return {k: {"count":len(group), "before":sum(r["original_status"] == "supported_by_review" for r in group),
                "after":sum(r["after"] for r in group)}
            for k in ("fixed_negative","development_diagnosis") if (group := [r for r in data if r["scope"] == k])}


def verify_live(run):
    receipt = read(EVIDENCE / f"web-{run}.json")
    path = ROOT / "runs" / run / "events.jsonl"
    events = journal(path)
    if file_hash(path) != receipt["journal_sha256"] or events[-1]["event"] != "run_finished":
        raise ValueError("Incomplete or different run")
    outcome = events[-1]["result"]
    analysis = outcome["analysis"]
    response, = (e["action"] for e in events if e.get("phase") == "card_verdict" and e["event"] == "model_response")
    sha = outcome["sample_sha256"]
    support, checks, calls = replay_screen(run,events,analysis,sha,
                                          require_link_read=analysis["report_method"] == "evidence-cards/17")
    baseline = enforce_stealer_support({"claims": analysis["claims"],"verdict": response["verdict"],
        "verdict_claim_ids": response["verdict_claim_ids"],"validation_notes":[]}, support)
    selected = {e["fact_id"]:e["claim_id"] for e in events if e["event"] == "operation_review_decision" and e["selected"]}
    replayed = recover(baseline,records_for(run),sha,selected)
    if (checks != analysis["role_checks"] or replayed != analysis["send_recovery"]
            or replayed != receipt["send_recovery"] or baseline["verdict_support"] != receipt["support_after_recovery"]
            or any(baseline[k] != analysis[k] for k in ("verdict","verdict_support","verdict_claim_ids"))):
        raise ValueError("Different verdict, roles, witnesses or operation recovery")
    return {"run":run,"replayed_model_calls":len(calls),"checks":len(checks),"verdict":baseline["verdict"]}


def live_comparison():
    """Use the published attempts in time order, including the interrupted one."""
    receipts = [read(EVIDENCE / f"web-{r}.json") for r in (PYTHON_RUN, STOPPED_RUN, RETRY_RUN)]
    baseline, stopped, latest = receipts
    if (any(len({r[k] for r in receipts}) != 1 for k in ("sha256","model_digest","config_sha256_excluding_sample"))
            or stopped["status"] != "incomplete" or stopped["termination"]["error_class"] != "ResourceBudgetExceeded"):
        raise ValueError("Different samples, settings or first attempt")
    comparison = []
    for receipt in (baseline, latest):
        run = receipt["run"]
        if receipt["status"] == "incomplete":
            comparison.append({"run":run, "status":"incomplete"})
            continue
        grade = read(EVIDENCE / f"transfer-live-{run}.json")
        if (grade["journal_sha256"] != receipt["journal_sha256"] or grade["verdict"] != receipt["verdict"]
                or grade["run"] != run or grade["accepted"] != receipt["accepted_claims"]
                or grade["unmatched"] or grade["graded_score"] is None):
            raise ValueError("Missing or different report grades")
        comparison.append({"run":run,"verdict":receipt["verdict"],"grade":grade["graded_score"],
                           "restored":[s["claim"] for s in receipt["send_recovery"]["sites"] if s["status"] == "recovered"],
                           "links":receipt["support_after_recovery"][LINK], "tool_calls":receipt["metrics"]["tool_calls"],
                           "tool_errors":receipt["metrics"]["tool_errors"],"seconds":receipt["metrics"]["elapsed_s"]})
    return {"completed_arms":comparison, "interrupted":stopped["run"],
            "same_claims":baseline["accepted_claim_keys_sha256"] == latest["accepted_claim_keys_sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    flags = parser.add_mutually_exclusive_group()
    flags.add_argument("--collect", action="store_true")
    flags.add_argument("--replay", action="store_true")
    flags.add_argument("--verify-live", metavar="RUN")
    flags.add_argument("--compare-runs", action="store_true")
    args = parser.parse_args()
    if args.collect:
        data = replay()
        check(data)
        dump_json(OUT, data)
    data = read(OUT)
    if args.replay and data != replay():
        raise ValueError("Bound VM evidence differs from the receipt")
    if args.verify_live:
        print(verify_live(args.verify_live))
    if args.compare_runs:
        print(live_comparison())
    print(check(data))
