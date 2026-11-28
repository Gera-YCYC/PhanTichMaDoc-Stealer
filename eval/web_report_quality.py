"""Read the three published audits or reproduce them locally from the terminal journals."""

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from stealer_agent.journal import canonical
from eval.score_public_batch import metrics, summarize_public_batch

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "deliverables/real-demo-evidence"
PROFILE = ROOT / "eval/reference_units/python2024.atomic-v3.json"


def read(path):
    return json.loads(path.read_bytes())


def dotnet_profiles():
    batch = read(EVIDENCE / "web-current-batch.json")
    profiles = {}
    for row in batch["runs"]:
        if row["sample"] in {"public_gomorrah.bin", "public_mercurial.bin"}:
            key = row["sample"].removeprefix("public_").removesuffix(".bin")
            profiles[key] = (row["run_id"], PROFILE.parent / f"{key}.atomic-v1.json")
    return profiles


def current_batch():
    path = EVIDENCE / "web-current-batch.json"
    runs = read(path)["runs"]
    reviews = {}
    for row in runs:
        root = (
            "web-python-quality"
            if row["sample"] == "public_python2024.bin"
            else "web-dotnet-quality"
        )
        reviews[row["run_id"]] = EVIDENCE / root / row["run_id"]
    profiles = [PROFILE, *(path for _, path in dotnet_profiles().values())]
    results = summarize_public_batch(path, profiles, review_directories=reviews)
    results["timings"] = [
        {
            "sample": row["sample"],
            "run": row["run_id"],
            "verdict": row["verdict"],
            "accepted": row["accepted_claims"],
            "proposed": row["proposed_claims"],
            "metrics": row["metrics"],
        }
        for row in runs
    ]
    return results


def reports(*, replay=False, sample="python"):
    series = read(EVIDENCE / "web-stability-python.json")
    profile_path = PROFILE
    review_root = "web-python-quality"
    if sample != "python":
        run, profile_path = dotnet_profiles()[sample]
        row = next(
            r
            for r in read(EVIDENCE / "web-current-batch.json")["runs"]
            if r["run_id"] == run
        )
        if (
            row["config_sha256_excluding_sample"] != series["configuration_sha256"]
            or row["model"]["digest"] != series["model_digest"]
            or row["source_manifest_sha256"] != series["source_manifest_sha256"]
        ):
            raise ValueError(
                "Different model, settings or agent revision in cross-format comparison"
            )
        series = {
            **series,
            "runs": [run],
            "journal_sha256": [row["journal"]["sha256"]],
            "sample_sha256": row["sample_sha256"],
        }
        review_root = "web-dotnet-quality"
    profile = read(profile_path)
    profile_hash = sha256(profile_path.read_bytes()).hexdigest()
    declared = {u["id"]: u["kind"] for u in profile["units"]}
    target_kinds = {"ioc", "attack"}
    if sample == "python" and (
        len(set(series["runs"])) != 3 or len(series["runs"]) != 3
    ):
        raise ValueError("Expected three distinct terminal runs")
    exposure = read(EVIDENCE / f"web-{sample}-exposure.json")["runs"]
    if [item["run"] for item in exposure] != series["runs"]:
        raise ValueError("Different exposure cohort")
    cohort = []
    for run, journal_hash, visibility in zip(
        series["runs"], series["journal_sha256"], exposure, strict=True
    ):
        folder = EVIDENCE / review_root / run
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
                score(original, profile_path, judgments, rebuilt)
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
    parser.add_argument("--sample", default="all")
    args = parser.parse_args()
    for name in (
        ["python", *dotnet_profiles()] if args.sample == "all" else [args.sample]
    ):
        for result in reports(replay=args.replay, sample=name):
            print(result["run"], result["raw"]["f1"], result["after_filter"]["f1"])
    if args.sample == "all":
        batch = current_batch()
        print(
            "Micro F1:",
            batch["after_filter"]["declared_units"]["f1"],
            "samples:",
            batch["total_attempts"],
        )
