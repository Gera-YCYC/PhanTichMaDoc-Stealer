"""Check exact static send retrieval on the previously labeled claim-role pairs."""
import argparse
from collections import Counter

from eval.ordinal_review_study import journal
from eval.role_line_study import NAVIGATION, PLAN, controls, file_hash
from eval.verdict_trial import EVIDENCE, ROOT, digest, read
from lab_web.cases import records_for
from stealer_agent.journal import dump_json
from stealer_agent.send_recovery import SEND, reviewed_sites

OUT = EVIDENCE / "send-site-retrieval.json"


def extract():
    plan = read(PLAN)
    cases = []
    for group in controls(plan):
        run = group["run"]
        path = ROOT / "runs" / run / "events.jsonl"
        if file_hash(path) != plan["report_journals"][run]:
            raise ValueError("Original journal changed")
        events = journal(path)
        result = events[-1]["result"]
        choices = {e["fact_id"]: e["claim_id"] for e in events
                   if e["event"] == "operation_review_decision" and e["selected"]}
        claims = result["analysis"]["claims"]
        sites = list(reviewed_sites(claims, records_for(run), result["sample_sha256"], choices))
        pairs = []
        for p in group["probes"]:
            if p["role"] != SEND:
                continue
            claim, = (c for c in claims if c["id"] == p["claim"])
            if digest(claim) != p["claim_sha256"]:
                raise ValueError("Original claim changed")
            pairs.append({"claim": p["claim"], "claim_sha256": p["claim_sha256"],
                          "expected": p["expected"], "found": any(s["claim"] == p["claim"] for s in sites)})
        cases.append({"run": run, "journal": file_hash(path), "sites": sites, "pairs": pairs})
    return {"protocol": file_hash(PLAN), "cases": cases}


def check(data):
    plan = read(PLAN)
    navigation = {r["run"]: r["screens"][0]["opened"] for r in read(NAVIGATION)}
    if data["protocol"] != file_hash(PLAN):
        raise ValueError("Unrecognized labels")
    scores = Counter()
    for case, group in zip(data["cases"], controls(plan), strict=True):
        if (case["run"] != group["run"] or case["journal"] != plan["report_journals"][group["run"]]
                or case["journal"] != read(EVIDENCE / f"web-{case['run']}.json")["journal_sha256"]):
            raise ValueError("Wrong source run")
        known = {s["claim"] for s in case["sites"]}
        spans = [{"claim":s["claim"], "fact":s["fact"],
                  "spans":[[r["line"],r["end"],r["output_sha256"]] for r in s["refs"]]} for s in case["sites"]]
        if spans != navigation.get(case["run"], []):
            raise ValueError("Different operation or source coordinates from the prior browser observations")
        probes = [p for p in group["probes"] if p["role"] == SEND]
        for row, p in zip(case["pairs"], probes, strict=True):
            if (any(row[k] != p[k] for k in ("claim", "claim_sha256", "expected"))
                    or row["found"] != (row["claim"] in known)):
                raise ValueError("Label or exact-citation result differs")
            scores[("TP" if row["expected"] else "FP") if row["found"] else
                   ("FN" if row["expected"] else "TN")] += 1
    return {k: scores[k] for k in ("TP", "FP", "FN", "TN")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--collect", action="store_true")
    group.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    if args.collect:
        data = extract()
        check(data)
        dump_json(OUT, data)
    data = read(OUT)
    if args.replay and extract() != data:
        raise ValueError("Original source and published results differ")
    print(check(data))
