"""Compare two live argument checks with the earlier three-run development series."""
import argparse
from hashlib import sha256

from eval.report_series import PUBLIC as PREVIOUS_SERIES
from eval.score_public_batch import metrics
from eval.transfer_report_audit import require
from eval.web_report_quality import EVIDENCE, PROFILE, read


RUNS = ("20261128T084808_81ca89a3", "20261128T085636_4eaac445")


def review(*, private=False):
    prior = read(PREVIOUS_SERIES)
    profile = read(PROFILE)
    unit = next(u for u in profile["units"] if u["id"] == "PY24-A09")
    required = {n for r in unit["source_references"] for n in range(r["line"], r["end_line"] + 1)}
    rows = []
    for run in RUNS:
        live = read(EVIDENCE / f"web-{run}.json")
        grade = read(EVIDENCE / f"transfer-live-{run}.json")
        proof = live["argument_browser"]
        covered = {n for a, b, _ in proof["spans"] for n in range(a, b + 1)}
        score = grade["graded_score"]
        require(live["run"] == grade["run"] == run and not grade["unmatched"]
                and live["journal_sha256"] == grade["journal_sha256"]
                and live["sha256"] == profile["sample_sha256"] == prior["series"]["sample_sha256"]
                and live["model_digest"] == prior["series"]["model_digest"]
                and live["config_sha256_excluding_sample"] == prior["series"]["configuration_sha256"]
                and grade["source_profile_sha256"] == sha256(PROFILE.read_bytes()).hexdigest(),
                "Different run, profile, configuration or model")
        require(metrics(score) == score and score["correct"] + score["missed"] == len(profile["units"]),
                "Scoring totals differ")
        edges = {e["id"]: e["status"] for e in live["terminal_edges"]}
        require(edges["rows-process"] == "supported" and live["displayed_edges_match_terminal"]
                and required <= covered and set(proof["roles"].values()) <= covered,
                "Incomplete argument evidence")
        clicked = next((c for c in grade["interaction"]["claims"] if c["id"] == proof["claim"]), None)
        require(bool(clicked) == proof["retained"], "Different final report decision")
        if clicked:
            require(proof["spans"] == [[r["first"], r["last"], r["output_sha256"]] for r in clicked["sources"]],
                    "Browser opened a different source in the report")
        if private:
            from eval.transfer_live_audit import check
            from scripts.export_investigation_receipt import export
            replay = check(run, grade["interaction"], include_decisions=True)
            decisions = replay.pop("decisions")
            require(replay == grade and export(run)["argument_browser"] == proof, "Private replay differs")
            decision = next(c for c in decisions if c["id"] == proof["claim"])
            require(decision["retained"] == proof["retained"] and (not proof["retained"]
                    or ["PY24-A09", "correct"] in [list(a) for a in decision["atoms"]]), "Different A09 grade")
        rows.append({"run": run, "claim": proof["claim"], "retained": proof["retained"],
                     "score": score, "supported": sum(v == "supported" for v in edges.values()),
                     "edges": len(edges), "verdict": grade["verdict"], "step": proof["step"],
                     "model_calls": live["metrics"]["model_calls"], "tool_calls": live["metrics"]["tool_calls"],
                     "seconds": live["metrics"]["elapsed_s"]})
    return {"runs": rows, "units": len(profile["units"]), "baseline": prior["summary"]["score_per_run"],
            "target_verdict": prior["summary"]["verdict_target"]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--private", action="store_true", help="Verify against the original lab journals")
    print(review(private=p.parse_args().private))
