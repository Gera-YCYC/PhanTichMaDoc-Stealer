"""Measure development reports and completion separately on the preselected three samples."""
import argparse
from hashlib import sha256

from eval.report_series import COMPLETE
from eval.score_public_batch import metrics
from eval.transfer_live_audit import check
from eval.transfer_report_audit import require
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, dotnet_profiles, read
from lab_web.cases import RUN
from stealer_agent.journal import dump_json

PUBLIC = EVIDENCE / "argument-cross-format.json"
PROTOCOL = ROOT / "eval/adjudications/argument-three-sample-protocol.json"
FIELDS = ("correct", "incorrect", "unsupported", "missed")


def measure(ids, *, private=False):
    plan = read(PROTOCOL)
    require(len(ids) == len(set(ids)) == 3 and all(RUN.fullmatch(i) for i in ids)
            and sorted(ids) == list(ids) and ids[0] == plan["python_run"], "Different order or cohort")
    paths = [PROFILE, *(dotnet_profiles()[s][1] for s in ("gomorrah", "mercurial"))]
    corpus = read(ROOT / "eval/corpora/real-yara-development-v3.json")["corpora"]
    truth = {item["sha256"]: "malicious" if item["positive"] else "benign"
             for values in corpus.values() for item in values}
    rows = []
    for run, sample, path in zip(ids, plan["sample_order"], paths, strict=True):
        live = read(EVIDENCE / f"web-{run}.json")
        profile = read(path)
        require(live["source_manifest_sha256"] == plan["source_manifest_sha256"]
                and live["config_sha256_excluding_sample"] == plan["configuration_sha256"]
                and live["model_digest"] == plan["model_digest"] and live["sample"] == sample
                and live["run"] == run and live["sha256"] == profile["sample_sha256"], "Different sample, model or core")
        score = None
        finished = live["status"] in COMPLETE
        if finished:
            grade = read(EVIDENCE / f"transfer-live-{run}.json")
            require(grade["run"] == run and grade["journal_sha256"] == live["journal_sha256"]
                    and grade["source_profile_sha256"] == sha256(path.read_bytes()).hexdigest()
                    and grade["verdict"] == live["verdict"] and not grade["unmatched"], "Different or incomplete grading")
            score = grade["graded_score"]
            require(score == metrics(score) and len(profile["units"]) == score["correct"] + score["missed"],
                    "Incorrect denominator")
            if private:
                require(check(run, grade["interaction"]) == grade, "Different private grading")
        else:
            require(live["status"] == "incomplete" and live.get("termination"), "Missing stop record")
        rows.append({"run": run, "sample": sample, "truth": truth[live["sha256"]],
                     "status": live["status"], "termination": live.get("termination"), "units": len(profile["units"]),
                     "verdict": live["verdict"] if finished else None, "score": score,
                     "tools": live["tools"], "tool_calls": live["metrics"]["tool_calls"],
                     "seconds": live["metrics"]["elapsed_s"], "model_calls": live["metrics"]["model_calls"],
                     "yara": [s["matched"] for s in live["yara"]], "journal_sha256": live["journal_sha256"]})
    if private:
        from scripts.compare_demo_batch import compare
        batch = compare(ids)
        attempts = [p.parent.name for p in sorted((ROOT / "runs").glob("*/events.jsonl"))
                    if RUN.fullmatch(p.parent.name) and ids[0] <= p.parent.name <= ids[-1]]
        require(attempts == list(ids) and batch["distinct_attempted_samples_with_terminal_journal"] == 3
                and [r["journal"]["sha256"] for r in batch["runs"]] == [r["journal_sha256"] for r in rows],
                "Intervening attempt or journal mismatch")
    completed = [r for r in rows if r["score"] is not None]
    evaluated = {k: sum(r["score"][k] for r in completed) for k in FIELDS}
    return {"protocol_sha256": sha256(PROTOCOL.read_bytes()).hexdigest(), "runs": rows,
            "completed": len(completed), "score_completed_only": metrics(evaluated) if completed else None,
            "correct_final_verdicts": sum(r["verdict"] == r["truth"] for r in completed),
            "attempted_reference_units": sum(r["units"] for r in rows)}


def published():
    saved = read(PUBLIC)
    require(measure([r["run"] for r in saved["runs"]]) == saved, "Published batch differs")
    return saved


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", nargs=3, metavar="RUN")
    args = parser.parse_args()
    if args.write:
        dump_json(PUBLIC, measure(args.write, private=True))
    result = published()
    print(result["completed"], "completed of 3,", result["score_completed_only"])
