"""Read the three published audits or reproduce them locally from the terminal journals."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from stealer_agent.journal import canonical
from eval.score_public_batch import metrics

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "deliverables/real-demo-evidence"
PROFILE = ROOT / "eval/reference_units/python2024.atomic-v3.json"


def read(path):
    return json.loads(path.read_bytes())


def reports(*, replay=False):
    series = read(EVIDENCE / "web-stability-python.json")
    profile = read(PROFILE)
    profile_hash = sha256(PROFILE.read_bytes()).hexdigest()
    declared = {u["id"]: u["kind"] for u in profile["units"]}
    target_kinds = {"ioc", "attack"}
    if len(set(series["runs"])) != 3 or len(series["runs"]) != 3:
        raise ValueError("Expected three distinct terminal runs")
    exposure = read(EVIDENCE / "web-python-exposure.json")["runs"]
    if [item["run"] for item in exposure] != series["runs"]:
        raise ValueError("Different exposure cohort")
    cohort = []
    for run, journal_hash, visibility in zip(
        series["runs"], series["journal_sha256"], exposure, strict=True
    ):
        folder = EVIDENCE / "web-python-quality" / run
        judgments = read(folder / "judgments.json")
        audit = read(folder / "source-audit.json")
        atoms = read(folder / "atomic-mapping.json")
        scored = read(folder / "atomic-score.json")
        scored_sentences = read(folder / "claim-score.json")
        receipt = read(EVIDENCE / f"web-{run}.json")
        if (
            any(
                r["run_id"] != run for r in [judgments, audit, scored, scored_sentences]
            )
            or any(
                r["profile_sha256"] != profile_hash for r in [judgments, atoms, scored]
            )
            or len(
                {
                    r["raw_report_sha256"]
                    for r in [judgments, audit, atoms, scored, scored_sentences]
                }
            )
            != 1
            or audit["journal_sha256"] != journal_hash
            or receipt["journal_sha256"] != journal_hash
            or receipt["run"] != run
            or receipt["model_digest"] != series["model_digest"]
            or receipt["source_manifest_sha256"] != series["source_manifest_sha256"]
            or receipt["verdict"] != scored_sentences["checked_verdict"]
            or len(
                {
                    r["sample_sha256"]
                    for r in [profile, series, audit, atoms, scored_sentences]
                }
                | {receipt["sha256"]}
            )
            != 1
            or judgments["checked_report_sha256"] != atoms["checked_report_sha256"]
        ):
            raise ValueError(f"Mismatched source or report for {run}")
        locations = {r["unit"]: r["category"] for r in visibility["units"]}
        kept_units = set(scored["after_filter"]["matched_reference_ids"])
        raw_units = set(scored["raw"]["matched_reference_ids"])
        if (
            visibility["journal_sha256"] != journal_hash
            or visibility["profile_sha256"] != profile_hash
            or len(locations) != len(visibility["units"])
            or locations.keys() != declared.keys()
            or Counter(locations.values()) != visibility["counts"]
            or {uid for uid, category in locations.items() if category == "retained"}
            != kept_units
            or {
                uid
                for uid, category in locations.items()
                if category == "lost_at_review"
            }
            != raw_units - kept_units
        ):
            raise ValueError(
                f"Exposure categories differ from the graded report for {run}"
            )
        retained = set(judgments["retained_ids"])
        decisions = {c["claim_id"]: c for c in audit["claims"]}
        parts = {c["claim_id"]: c["atoms"] for c in atoms["claims"]}
        if (
            set(decisions) != set(parts)
            or set(decisions) != set(judgments["claims"])
            or len(decisions) != len(audit["claims"])
            or len(parts) != len(atoms["claims"])
            or not retained <= set(decisions)
            or len(retained) != receipt["accepted_claims"]
            or len(judgments["retained_ids"]) != len(retained)
        ):
            raise ValueError(f"Incomplete grading table for {run}")
        stages = {}
        for stage, ids in (("raw", set(decisions)), ("after_filter", retained)):
            unique = {}
            for cid in ids:
                kind = judgments["claims"][cid]["kind"]
                for part in parts[cid]:
                    key, label = part["unit_key"], part["label"]
                    if unique.setdefault(key, (kind, label)) != (kind, label):
                        raise ValueError(f"Conflicting judgments for {key}")
            scores = []
            for kinds, expected in (
                (
                    set(declared.values()) | {k for k, _ in unique.values()},
                    scored[stage],
                ),
                (target_kinds, scored["rubric_ioc_attack"][stage]),
            ):
                refs = {key for key, kind in declared.items() if kind in kinds}
                hits = {
                    key for key in refs if unique.get(key) == (declared[key], "correct")
                }
                labels = Counter(
                    label for kind, label in unique.values() if kind in kinds
                )
                actual = metrics(
                    dict(
                        correct=len(hits),
                        missed=len(refs - hits),
                        incorrect=labels["incorrect"],
                        unsupported=labels["unsupported"],
                    )
                )
                if any(expected[key] != value for key, value in actual.items()):
                    raise ValueError(f"Atomic score mismatch for {run}, {stage}")
                scores.append(actual)
            labels = Counter(decisions[i]["label"] for i in ids)
            cited = sum(bool(decisions[i]["truth_reference"]) for i in ids)
            if (
                labels != Counter(scored_sentences[stage]["counts"])
                or len(ids) != scored_sentences[stage]["claim_count"]
                or cited != scored_sentences[stage]["verified_tool_citation_count"]
            ):
                raise ValueError(f"Sentence score mismatch for {run}, {stage}")
            stages[stage] = {
                **scores[0],
                "claims": len(ids),
                "sentence_counts": dict(labels),
                "cited": cited,
                "ioc_attack_f1": scores[1]["f1"],
            }
        if replay:
            from scripts.score_reviewed_run import score

            original = ROOT / "runs" / run
            checked = read(original / "report.private.json")["analysis"]
            if (
                sha256(canonical(checked)).hexdigest()
                != judgments["checked_report_sha256"]
                or retained != {c["id"] for c in checked["claims"]}
                or any(
                    judgments["claims"][c["id"]]["kind"] != c["kind"]
                    for c in read(original / "report.model-raw.json")["claims"]
                )
                or sha256((original / "events.jsonl").read_bytes()).hexdigest()
                != journal_hash
            ):
                raise ValueError(f"Terminal report differs for {run}")
            with TemporaryDirectory() as tmp:
                rebuilt = Path(tmp)
                score(original, PROFILE, judgments, rebuilt)
                for artifact in rebuilt.iterdir():
                    if artifact.suffix == ".json":
                        equal = read(artifact) == read(folder / artifact.name)
                    else:
                        equal = artifact.read_text(encoding="utf8") == (
                            folder / artifact.name
                        ).read_text(encoding="utf8")
                    if not equal:
                        raise ValueError(
                            f"Local replay differs for {run}/{artifact.name}"
                        )
        rows = [
            {
                "id": cid,
                "summary": judgments["claims"][cid]["public_summary"],
                "reason": d["reason"],
                "label": d["label"],
                "retained": cid in retained,
                "lines": [[r["line"], r["end_line"]] for r in d["truth_reference"]],
            }
            for cid, d in decisions.items()
        ]
        cohort.append(
            {
                "run": run,
                **stages,
                "verdict": receipt["verdict"],
                "rows": rows,
                "reference_count": len(declared),
                "missed": [
                    {
                        "id": u["id"],
                        "proposition": u["proposition"],
                        "category": locations[u["id"]],
                    }
                    for u in profile["units"]
                    if u["id"] not in kept_units
                ],
            }
        )
    return cohort


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Verify local journals and reproduce every grading artifact",
    )
    for result in reports(replay=parser.parse_args().replay):
        print(result["run"], result["raw"]["f1"], result["after_filter"]["f1"])
