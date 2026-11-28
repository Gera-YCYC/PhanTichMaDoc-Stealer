"""Compare two complete Mercurial investigations and audit the claim roles at catch sites."""
import argparse
from collections import Counter
import json

from eval.ordinal_review_study import claim_quality, live_arm, sentence_rates
from eval.score_public_batch import metrics
from eval.table_access_study import STATES, extract, file_hash
from eval.transfer_live_audit import check
from eval.transfer_report_audit import require
from eval.web_report_exposure import events
from eval.web_report_quality import ROOT, EVIDENCE, read
from lab_web.cases import RUN, case, records_for
from stealer_agent.operation_context import valid_operations
from stealer_agent.journal import canonical, dump_json
from hashlib import sha256

PLAN = ROOT / "eval/adjudications/catch-argument-protocol.json"
PUBLIC = EVIDENCE / "catch-argument-study.json"


def capture_arm(run, plan):
    profile = read(ROOT / plan["profile"])
    state = extract(run, profile, True)
    result = live_arm(run)
    result.update(coverage=state["states"], sentences=[], atoms=[], table_credits=[])
    if result["score"] is not None:
        grade = read(EVIDENCE / f"transfer-live-{run}.json")
        audited = check(run, grade["interaction"], include_decisions=True)
        decisions = audited.pop("decisions")
        result["sentences"] = claim_quality(run, decisions)
        result["atoms"] = [{"id": r["id"], "signature": r["signature"], "atoms": [list(pair) for pair in r["atoms"]]}
                           for r in decisions if r["retained"]]
        require(audited == grade, "Private and published grades differ")
        facts = {f["fact_id"]: f for rec in records_for(run).values() for f in valid_operations(rec)}
        tables = {"cookies":"cookie-table", "logins":"login-table"}
        for site in case(run)["reader_fields"]:
            f = facts[site["id"]]
            uid = tables.get(f["inputs"]["table"])
            if not site["claim"] or uid is None:
                continue
            unit = next(u for u in profile["units"] if u["id"] == uid)
            refs = site["refs"]
            require(all(s["evidence_id"] == profile["source_record"]["evidence_id"] and any(
                            r["line"] <= s["line"] and r["end"] >= s["end_line"] and r["output_sha256"] == profile["source_record"]["output_sha256"]
                            for r in refs) for s in unit["source_references"]), "Table source differs")
            result["table_credits"].append({"id":site["claim"], "fact":site["id"], "unit":uid,
                                           "spans":[[r["line"],r["end"],r["output_sha256"]] for r in refs]})
    return result


def eligibility(trace, view):
    sites = []
    votes = {e["fact_id"]: e for e in trace if e["event"] == "operation_review_decision"}
    terminal = trace[-1]["result"]["analysis"]
    requests = [e for e in trace if e["event"] == "model_request" and e["phase"] == "card_verdict"]
    allowed = set()
    if requests:
        req, = requests
        require(sha256(canonical(req["messages"])).hexdigest() == req["messages_sha256"], "Verdict input changed")
        allowed = {c["id"] for c in json.loads(req["messages"][-1]["content"])}
        enums = req["schema"]["properties"]
        require(all(set(enums[key]["items"]["enum"]) == allowed for key in terminal["verdict_support"]),
                "Different verdict choices")
    for s in view["catch_sites"]:
        vote = votes.get(s["id"])
        cid = s["claim"]
        if cid:
            require(vote and vote["selected"] and vote["claim_id"] == cid and s["context_only"]
                    and cid not in allowed and cid not in terminal["verdict_claim_ids"]
                    and all(cid not in values for values in terminal["verdict_support"].values()),
                    "Handler argument was used as verdict evidence")
        sites.append({"fact": s["id"], "spans": [[r["line"], r["end"], r["output_sha256"]] for r in s["refs"]],
                      "reviewed": vote is not None, "claim": cid, "context_only": s["context_only"],
                      "overlapping": [{"id": other, "roles": [key for key, ids in terminal.get("verdict_support", {}).items() if other in ids]}
                                      for other in s["overlapping_claims"]]})
    require({s["claim"] for s in sites if s["context_only"]} == set(terminal.get("catch_context_claim_ids", [])),
            "Unbound verdict exclusion")
    return sites


def count_atoms(rows, units, exclude):
    labels = {}
    for row in rows:
        if row["id"] in exclude:
            continue
        for uid, label in row["atoms"]:
            require(labels.setdefault(uid, label) == label, "Conflicting grades for one atomic unit")
    correct = {uid for uid in units if labels.get(uid) == "correct"}
    return {"covered": sorted(correct), "score": metrics({"correct": len(correct), "missed": len(units-correct),
            "incorrect": list(labels.values()).count("incorrect"), "unsupported": list(labels.values()).count("unsupported")})}


def contribution(rows, units, sites):
    ids = {s["claim"] for s in sites if s["claim"]}
    require(ids <= {r["id"] for r in rows}, "Ablation refers to a missing claim")
    complete = count_atoms(rows, units, set())
    reduced = count_atoms(rows, units, ids)
    return {"omitted_ids": sorted(ids), "without": reduced["score"], "with": complete["score"],
            "unique_units": sorted(set(complete["covered"]) - set(reduced["covered"]))}


def build(run):
    plan = read(PLAN)
    require(RUN.fullmatch(run), "Expected a run ID")
    ids = []
    for log in sorted((ROOT / "runs").glob("*/events.jsonl")):
        if RUN.fullmatch(log.parent.name):
            with log.open("rb") as stream:
                start = json.loads(stream.readline())
            if start.get("sample") == plan["sample"] and start["timestamp"] > plan["registered"]:
                ids.append(log.parent.name)
    require(ids and ids[0] == run, "Omitted first subsequent attempt")
    trace = events(run)
    manifest = next(e["files"] for e in trace if e["event"] == "source_version")
    require(all(manifest.get(k) == v for k, v in plan["core"].items()), "Different candidate revision")
    arms = [capture_arm(r, plan) for r in (plan["baseline"], run)]
    sites = eligibility(trace, case(run))
    return {"plan_sha256": file_hash(PLAN), "arms": arms, "sites": sites}


def published():
    plan, data = read(PLAN), read(PUBLIC)
    before, after = data["arms"]
    require(data["plan_sha256"] == file_hash(PLAN) and file_hash(ROOT / plan["profile"]) == plan["profile_sha256"]
            and file_hash(ROOT / "config/host.investigation.example.json") == plan["config_sha256"]
            and before["run"] == plan["baseline"] and before["journal"] == plan["journal_sha256"]
            and after["run"] > before["run"], "Published experiment differs from its protocol")
    profile = read(ROOT / plan["profile"])
    units = {u["id"] for u in profile["units"]}
    reports = []
    for a in data["arms"]:
        run = a["run"]
        live = read(EVIDENCE / f"web-{run}.json")
        reports.append(live)
        require(live_arm(run) == {k: v for k, v in a.items() if k not in {"coverage", "sentences","atoms","table_credits"}}
                and set(a["coverage"]) == units and set(a["coverage"].values()) <= STATES, "Different report or coverage")
        if a["score"] is not None:
            require(len(a["sentences"]) == a["claims"] and list(a["coverage"].values()).count("retained") == a["score"]["correct"],
                    "Incorrect denominators")
    require(all(reports[0][k] == reports[1][k] for k in ("sha256", "model_digest", "config_sha256_excluding_sample"))
            and reports[1]["sha256"] == profile["sample_sha256"] and reports[0]["source_manifest_sha256"] != reports[1]["source_manifest_sha256"],
            "Model, sample or configuration mismatch")
    sites = data["sites"]
    require(len({s["fact"] for s in sites}) == len(sites) and all(s["spans"] and all(
        0 < a <= b and digest == profile["source_record"]["output_sha256"] for a, b, digest in s["spans"])
        and bool(s["claim"]) == s["context_only"] and (not s["claim"] or s["reviewed"]) for s in sites),
        "Invalid source or verdict scope")
    corrected = []
    for a in data["arms"]:
        atoms = a["atoms"]
        require([(r["id"],r["signature"],[label for _,label in r["atoms"]]) for r in atoms] ==
                [(r["claim"],r["signature"],r["labels"]) for r in a["sentences"]], "Different graded claims")
        extra = {r["id"]:r for r in a["table_credits"]}
        require(len(extra) == len(a["table_credits"]) and set(extra) <= {r["id"] for r in atoms}, "Unbound table grade")
        for r in extra.values():
            unit = next(u for u in profile["units"] if u["id"] == r["unit"])
            require(r["unit"] in {"cookie-table","login-table"} and all(s["evidence_id"] == profile["source_record"]["evidence_id"] and any(
                n <= s["line"] and m >= s["end_line"] and h == profile["source_record"]["output_sha256"] for n,m,h in r["spans"]
            ) for s in unit["source_references"]), "Invalid table coordinates")
        rescored = [{**r, "atoms": [*r["atoms"], *([[extra[r["id"]]["unit"],"correct"]] if r["id"] in extra else [])]} for r in atoms]
        corrected.append(count_atoms(rescored,units,set()) if a["score"] else None)
    effect = contribution(after["atoms"], units, sites) if after["score"] is not None else None
    require(effect is None or effect["with"] == after["score"], "Ablation differs from the actual whole report")
    results = [{**{k:v for k,v in a.items() if k not in {"coverage","sentences","atoms","table_credits"}},
                "outcomes": dict(Counter(a["coverage"].values())), "rates": sentence_rates(a["sentences"])}
               for a in data["arms"]]
    return {"arms": results, "sites": sites, "contribution": effect, "table_regrade": corrected,
            "gained": sorted(k for k in units if before["coverage"][k] != "retained" and after["coverage"][k] == "retained"),
            "lost": sorted(k for k in units if before["coverage"][k] == "retained" and after["coverage"][k] != "retained")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", metavar="RUN")
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if args.write:
        dump_json(PUBLIC, build(args.write))
    result = published()
    if args.replay:
        require(build(result["arms"][1]["run"]) == read(PUBLIC), "Private replay differs")
    print(json.dumps(result, ensure_ascii=True))
