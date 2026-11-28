"""Verify exact stability and locate recurring omissions in three real Python reports."""

import argparse
from collections import Counter
from hashlib import sha256
import json
import re

from eval.score_public_batch import metrics
from eval.transfer_live_audit import check
from eval.transfer_report_audit import require
from eval.web_report_exposure import (
    events,
    reconstruct,
    request_windows,
    required_rows,
    source_id,
)
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, read
from eval.web_stability import evaluate
from lab_web.cases import RUN
from stealer_agent.journal import canonical, dump_json

PUBLIC = EVIDENCE / "staging-stability.json"
ARGUMENT_SERIES = EVIDENCE / "argument-stability.json"


ARGUMENT_RUNS = ("20261128T085636_4eaac445", "20261128T091615_0ffb665e", "20261128T092538_136e21fd")
COMPLETE = {"completed_needs_review", "completed_with_rejected_claims"}


def overlap(sets):
    common, union = set.intersection(*sets), set.union(*sets)
    return {
        "common": len(common),
        "union": len(union),
        "rate": len(common) / len(union) if union else None,
    }


def collect(run, origins):
    grade = read(EVIDENCE / f"transfer-live-{run}.json")
    replayed = check(run, grade["interaction"], include_decisions=True)
    decisions = replayed.pop("decisions")
    require(
        replayed == grade and not grade["unmatched"],
        "Incomplete or different source grades",
    )
    journal = events(run)
    profile = read(PROFILE)
    eid = source_id(profile, journal)
    source = reconstruct(journal)[eid]
    windows = request_windows(journal, eid, source["line_map"], include_flow=True)
    seen, together = [], []
    for unit in profile["units"]:
        rows = required_rows(unit, source, profile, origins)
        if rows <= source["line_map"].keys():
            seen.append(unit["id"])
        if any(rows <= window for window in windows):
            together.append(unit["id"])
    return {
        "run": run,
        "journal_sha256": grade["journal_sha256"],
        "decisions": decisions,
        "rows_in_tools": seen,
        "rows_in_one_prompt": together,
    }


def assemble(ids, *, argument=False):
    require(
        len(ids) == 3
        and len(set(ids)) == 3
        and ids == sorted(ids)
        and all(RUN.fullmatch(x) for x in ids),
        "Supply three distinct chronological run IDs",
    )
    if argument:
        require(tuple(ids) == ARGUMENT_RUNS, "Different consecutive Python attempts")
        receipts = [read(EVIDENCE / f"web-{run}.json") for run in ids]
        complete = [r for r in receipts if r["status"] in COMPLETE]
        require([r["run"] for r in complete] == ids[:2], "Different terminal outcomes")
        first = complete[0]
        base = {
            "runs": ids[:2], "sample": first["sample"], "sample_sha256": first["sha256"],
            "model_digest": first["model_digest"], "source_manifest_sha256": first["source_manifest_sha256"],
            "configuration_sha256": first["config_sha256_excluding_sample"],
            "journal_sha256": [r["journal_sha256"] for r in complete],
            "verdicts": [r["verdict"] for r in complete],
            "accepted_claim_counts": [r["accepted_claims"] for r in complete],
            "duration_seconds": [r["metrics"]["elapsed_s"] for r in complete],
            "tool_calls": [r["metrics"]["tool_calls"] for r in complete],
            "attempts": [{"run": r["run"], "status": r["status"], "journal_sha256": r["journal_sha256"]} for r in receipts],
            "claim_stability": None,
        }
    else:
        base = evaluate(ids)
    actual = []
    for p in sorted((ROOT / "runs").glob("*/events.jsonl")):
        if ids[0] <= p.parent.name <= ids[-1] and RUN.fullmatch(p.parent.name):
            with p.open("rb") as stream:
                first = json.loads(stream.readline())
            if first.get("sample") == base["sample"]:
                actual.append(p.parent.name)
    require(actual == ids, "One or more intervening sample attempts were omitted")
    origins = {}
    for r in ("20261127T211223_9602dfdd", "20261127T230331_8bd30a1f"):
        origins.update(reconstruct(events(r)))
    return {"series": base, "cases": [collect(run, origins) for run in base["runs"]]}


def analyze(data):
    base, cases = data["series"], data["cases"]
    ids = [r["run"] for r in cases]
    attempts = base.get("attempts")
    if attempts is not None:
        require([a["run"] for a in attempts] == list(ARGUMENT_RUNS)
                and ids == list(ARGUMENT_RUNS[:2]) and base["claim_stability"] is None,
                "Different membership or fabricated three-report stability")
        for i, item in enumerate(attempts):
            live = read(EVIDENCE / f"web-{item['run']}.json")
            require(item == {k: live[k] for k in ("run", "status", "journal_sha256")}
                    and live["sample"] == base["sample"] and live["sha256"] == base["sample_sha256"]
                    and live["model_digest"] == base["model_digest"]
                    and live["source_manifest_sha256"] == base["source_manifest_sha256"]
                    and live["config_sha256_excluding_sample"] == base["configuration_sha256"]
                    and live["status"] in (COMPLETE if i < 2 else {"incomplete"}),
                    "Different terminal attempt or configuration")
        stop = live["termination"]
        require(stop["error_class"] == "ResourceBudgetExceeded" and stop["model_unloaded"]
                and 0 < live["metrics"]["minimum_observed_host_available_memory_bytes"] < stop["memory_floor_bytes"]
                and not live["accepted_claims"] and not live["yara"], "Different incomplete terminal report")
    require(
        ids == base["runs"]
        and len(ids) == len(set(ids)) == (2 if attempts is not None else 3)
        and ids == sorted(ids)
        and all(RUN.fullmatch(x) for x in ids),
        "Expected three distinct terminal runs",
    )
    profile = read(PROFILE)
    units = {u["id"] for u in profile["units"]}
    profile_hash = sha256(PROFILE.read_bytes()).hexdigest()
    labels = read(ROOT / "eval/corpora/real-yara-development-v3.json")["corpora"]
    (truth,) = {
        r["positive"]
        for partition in labels.values()
        for r in partition
        if r["sha256"] == base["sample_sha256"]
    }
    verdict = "malicious" if truth else "benign"
    bound_grades = {}
    scores, accepted_sets, covered_sets, reviews = [], [], [], []
    states = {uid: [] for uid in sorted(units)}
    for i, case in enumerate(cases):
        run = case["run"]
        receipt = read(EVIDENCE / f"web-{run}.json")
        graded = read(EVIDENCE / f"transfer-live-{run}.json")
        require(
            receipt["run"] == graded["run"] == run
            and case["journal_sha256"]
            == receipt["journal_sha256"]
            == graded["journal_sha256"]
            == base["journal_sha256"][i]
            and base["source_manifest_sha256"] == receipt["source_manifest_sha256"]
            and base["configuration_sha256"]
            == receipt["config_sha256_excluding_sample"]
            and base["model_digest"] == receipt["model_digest"]
            and base["sample_sha256"] == receipt["sha256"] == profile["sample_sha256"]
            and profile_hash == graded["source_profile_sha256"]
            and not graded["unmatched"]
            and base["verdicts"][i] == graded["verdict"] == receipt["verdict"],
            "Changed report identity or configuration",
        )
        rows = case["decisions"]
        accepted = [r for r in rows if r["retained"]]
        keys_digest = sha256(canonical(sorted(r["key"] for r in accepted))).hexdigest()
        require(receipt["accepted_claim_keys_sha256"] == keys_digest, "Different terminal claim keys")
        require(
            len({r["id"] for r in rows}) == len(rows)
            and len(accepted)
            == graded["accepted"]
            == base["accepted_claim_counts"][i]
            == receipt["accepted_claims"],
            "Unbound decision count",
        )
        judged, lost = {}, set()
        for row in rows:
            require(
                row["kind"] in {"behavior", "attack", "ioc"}
                and all(
                    re.fullmatch("[a-f0-9]{64}", row[k]) for k in ("key", "signature")
                ),
                "Invalid claim fingerprint",
            )
            atoms = row["atoms"]
            if atoms is None:
                require(not row["retained"], "Missing grade on retained claim")
                continue
            require(
                bound_grades.setdefault(row["signature"], atoms) == atoms,
                "Conflicting proposition grades",
            )
            for uid, label in atoms:
                require(
                    label in {"correct", "incorrect", "unsupported"}, "Unknown grade"
                )
                if row["retained"]:
                    require(judged.setdefault(uid, label) == label, "Conflicting atom")
                elif uid in units and label == "correct":
                    lost.add(uid)
        covered = {uid for uid in units if judged.get(uid) == "correct"}
        counts = Counter(judged.values())
        score = metrics(
            dict(
                correct=len(covered),
                missed=len(units - covered),
                incorrect=counts["incorrect"],
                unsupported=counts["unsupported"],
            )
        )
        require(
            score == graded["graded_score"],
            "Source grades do not reproduce report score",
        )
        together = set(case["rows_in_one_prompt"])
        require(
            together <= set(case["rows_in_tools"]) <= units,
            "Inconsistent source exposure",
        )
        for uid in units:
            if uid in covered:
                state = "retained"
            elif uid in lost:
                state = "rejected_evidence"
            elif uid in together:
                state = "visible_in_one_prompt"
            elif uid in case["rows_in_tools"]:
                state = "retrieved"
            else:
                state = "incomplete_source"
            states[uid].append(state)
        scores.append(score)
        wordings = Counter()
        for row in accepted:
            judgments = {label for _, label in row["atoms"]}
            if not judgments:
                wordings["no_scoped_atoms"] += 1
            elif "unsupported" in judgments:
                wordings["unsupported"] += 1
            elif "incorrect" in judgments:
                wordings["incorrect"] += 1
            else:
                wordings["supported"] += 1
        reviews.append(
            {
                "sentence_labels": dict(wordings),
                "retained": len(accepted),
                "cited": sum(row["citation_count"] > 0 for row in accepted),
                "ungraded_rejections": [
                    r["id"] for r in rows if not r["retained"] and r["atoms"] is None
                ],
                "lost_at_review": [
                    {
                        "id": r["id"],
                        "units": sorted(
                            {
                                u
                                for u, label in r["atoms"]
                                if u in units - covered and label == "correct"
                            }
                        ),
                        "contains_error": any(
                            label != "correct" for _, label in r["atoms"]
                        ),
                    }
                    for r in rows
                    if not r["retained"]
                    and r["atoms"]
                    and any(
                        u in units - covered and label == "correct"
                        for u, label in r["atoms"]
                    )
                ],
            }
        )
        covered_sets.append(covered)
        accepted_sets.append({r["key"] for r in accepted})
    exact = overlap(accepted_sets)
    recorded = base["claim_stability"]
    require(
        attempts is not None or (exact["common"], exact["union"], exact["rate"])
        == (recorded["stable_claims"], recorded["union_claims"], recorded["stability"]),
        "Different slide stability",
    )
    return {
        "exact": exact,
        "score_per_run": scores,
        "reviews": reviews,
        "verdict_target": verdict,
        "correct_verdicts": base["verdicts"].count(verdict),
        "covered": sorted(set.intersection(*covered_sets)),
        "sometimes": sorted(set.union(*covered_sets) - set.intersection(*covered_sets)),
        "always_missing": sorted(units - set.union(*covered_sets)),
        "states": states,
    }


def changing_claims(cases):
    """Only compare review decisions as identical inputs when citations also match."""
    proposed = []
    accepted = []
    for case in cases:
        by_key = {}
        for row in case["decisions"]:
            by_key.setdefault(row["key"], []).append(row)
        proposed.append(by_key)
        accepted.append({k for k, rows in by_key.items() if any(r["retained"] for r in rows)})
    result = []
    for key in sorted(set.union(*accepted) - set.intersection(*accepted)):
        steps = [items.get(key, []) for items in proposed]
        all_rows = [r for step in steps for r in step]
        fingerprints = {}
        for i, step in enumerate(steps):
            for r in step:
                fingerprints.setdefault(r["signature"], {}).setdefault(i, set()).add(r["retained"])
        opposite = any(left != right and True in states and False in other
                       for by_run in fingerprints.values() for left, states in by_run.items()
                       for right, other in by_run.items())
        result.append({
            "kind": all_rows[0]["kind"], "key": key,
            "units": sorted({u for r in all_rows for u, label in r["atoms"] or []
                             if label == "correct" and u.startswith("PY24-A")}),
            "absent_in_drafts": any(not step for step in steps),
            "same_input_opposite_decisions": opposite,
            "steps": [[{"id": r["id"], "kept": r["retained"]} for r in step] for step in steps],
        })
    return result


def kind_scores(case, profile):
    """Use the same distinct-unit denominators as the published overall score."""
    groups = {k: {} for k in ("behavior", "ioc", "attack")}
    declared = {u["id"]: u["kind"] for u in profile["units"]}
    owners = dict(declared)
    for row in case["decisions"]:
        if row["retained"]:
            for uid, label in row["atoms"]:
                kind = row["kind"]
                require(owners.setdefault(uid, kind) == kind, "Ambiguous unit kind")
                require(groups[kind].setdefault(uid, label) == label, "Conflicting grade")
    result = {}
    for kind, judged in groups.items():
        units = {uid for uid, k in declared.items() if k == kind}
        correct = sum(judged.get(uid) == "correct" for uid in units)
        counts = Counter(judged.values())
        result[kind] = metrics(dict(correct=correct, missed=len(units)-correct,
                                    incorrect=counts["incorrect"], unsupported=counts["unsupported"]))
    return result


def web_results(path=PUBLIC):
    data = read(path)
    summary = analyze(data)
    require(summary == data["summary"], "Different published stability table")
    base = data["series"]
    links = []
    for case in data["cases"]:
        by_unit = {}
        for row in case["decisions"]:
            for uid, label in row["atoms"] or []:
                if label == "correct":
                    by_unit.setdefault((uid, row["retained"]), []).append(row["id"])
        links.append(by_unit)
    diagnostics = {}
    if path == ARGUMENT_SERIES:
        changing = changing_claims(data["cases"])
        require(len(changing) == summary["exact"]["union"] - summary["exact"]["common"],
                "Different number of changing claims")
        profile = read(PROFILE)
        by_kind = [kind_scores(c, profile) for c in data["cases"]]
        for groups, overall in zip(by_kind, summary["score_per_run"], strict=True):
            for field in ("correct", "incorrect", "unsupported", "missed"):
                require(sum(s[field] for s in groups.values()) == overall[field], "Different unit totals by kind")
        incomplete = read(EVIDENCE / f"web-{ARGUMENT_RUNS[-1]}.json")
        diagnostics = {"changed": changing, "by_kind": by_kind, "three_report_agreement": None,
                       "incomplete": {"run": incomplete["run"], **incomplete["termination"], **incomplete["metrics"]}}
    return {
        **diagnostics,
        "agreement": summary["exact"],
        "correct_verdicts": summary["correct_verdicts"],
        "counts": [len(summary[k]) for k in ("covered", "sometimes", "always_missing")],
        "runs": [
            {
                "run": run,
                "claims": base["accepted_claim_counts"][i],
                "verdict": base["verdicts"][i],
                "seconds": base["duration_seconds"][i],
                "tools": base["tool_calls"][i],
                **score,
            }
            for i, (run, score) in enumerate(
                zip(base["runs"], summary["score_per_run"], strict=True)
            )
        ],
        "units": [
            {
                "id": u["id"],
                "description": u["proposition"],
                "states": summary["states"][u["id"]],
                "claims": [
                    links[i].get((u["id"], state == "retained"), [])
                    if state in {"retained", "rejected_evidence"} else []
                    for i, state in enumerate(summary["states"][u["id"]])
                ],
            }
            for u in read(PROFILE)["units"]
        ],
    }


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--write", nargs=3, metavar="RUN")
    cli.add_argument("--replay", action="store_true")
    cli.add_argument("--argument", action="store_true", help="Use the series with the row-to-argument check")
    args = cli.parse_args()
    path = ARGUMENT_SERIES if args.argument else PUBLIC
    if args.write:
        data = assemble(args.write, argument=args.argument)
        # JSON round trip normalizes tuple grades to their portable representation.
        data = json.loads(canonical(data))
        data["summary"] = analyze(data)
        dump_json(path, data)
    else:
        data = read(path)
        require(analyze(data) == data["summary"], "Different published stability table")
        if args.replay:
            ids = list(ARGUMENT_RUNS) if args.argument else data["series"]["runs"]
            rebuilt = assemble(ids, argument=args.argument)
            require(
                canonical(rebuilt) == canonical({k: data[k] for k in rebuilt}),
                "Private journal replay differs",
            )
    summary = data["summary"]
    if args.argument:
        print(json.dumps({"attempts": 3, "completed": 2, "three_report_stability": None,
                          "completed_pair_only": summary["exact"], "correct_verdicts_completed_only": summary["correct_verdicts"]}))
    else:
        print(json.dumps({k: summary[k] for k in ("exact", "correct_verdicts", "always_missing")}))
