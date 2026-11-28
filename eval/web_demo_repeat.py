"""Transfer the existing source audit only when every proposed claim and citation matches."""

import argparse
import json
from hashlib import sha256

from eval.atomic_units import calculate
from eval.web_report_exposure import events, source_id
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, read
from scripts.replay_card_report import reconstruct
from scripts.score_reviewed_run import scoped_counts
from stealer_agent.journal import canonical, dump_json

ORIGINAL = "20261128T021511_bec5b2e5"
REPEAT = "20261128T035912_e9d2b879"


def load_run(run):
    folder = ROOT / "runs" / run
    receipt = read(EVIDENCE / f"web-{run}.json")
    journal = events(run)
    if (
        sha256((folder / "events.jsonl").read_bytes()).hexdigest()
        != receipt["journal_sha256"]
        or journal[-1]["event"] != "run_finished"
        or journal[-1]["result"] != read(folder / "report.private.json")
    ):
        raise ValueError("Missing or changed terminal analysis")
    eid = source_id(read(PROFILE), journal)
    lines = reconstruct(journal)[eid]["line_map"]
    raw = (folder / "report.model-raw.json").read_bytes()
    checked = journal[-1]["result"]["analysis"]
    fingerprints = []
    for c in json.loads(raw)["claims"]:
        if not c["evidence"] or any(ref["evidence_id"] != eid for ref in c["evidence"]):
            raise ValueError("Claim not bound to the same projected Python source")
        if any(
            ref["quote"]
            != "\n".join(lines[n] for n in range(ref["line"], ref["end_line"] + 1))
            for ref in c["evidence"]
        ):
            raise ValueError("Quote differs from original projected rows")
        content = {
            **c,
            "evidence": [
                {k: v for k, v in ref.items() if k != "evidence_id"}
                for ref in c["evidence"]
            ],
        }
        fingerprints.append(sha256(canonical(content)).hexdigest())
    return receipt, raw, checked, fingerprints


def compare():
    src, raw0, report0, digests0 = load_run(ORIGINAL)
    dest, raw, report, digests = load_run(REPEAT)
    if (
        digests != digests0
        or src["sha256"] != dest["sha256"]
        or src["model_digest"] != dest["model_digest"]
    ):
        raise ValueError(
            "Comparison requires identical proposals, source coordinates and model"
        )
    mapping_path = EVIDENCE / "web-python-quality" / ORIGINAL / "atomic-mapping.json"
    frozen = read(mapping_path)
    if (
        sha256(raw0).hexdigest() != frozen["raw_report_sha256"]
        or sha256(canonical(report0)).hexdigest() != frozen["checked_report_sha256"]
        or sha256(PROFILE.read_bytes()).hexdigest() != frozen["profile_sha256"]
    ):
        raise ValueError("Source audit corresponds to different reports")
    profile = read(PROFILE)
    extras = read(mapping_path.with_name("judgments.json"))["additional_findings"]
    augmented = canonical({**profile, "units": profile["units"] + extras})
    adapted = {
        **frozen,
        "profile_sha256": sha256(augmented).hexdigest(),
        "raw_report_sha256": sha256(raw).hexdigest(),
        "checked_report_sha256": sha256(canonical(report)).hexdigest(),
    }
    score = calculate(augmented, raw, canonical(report), adapted)
    first = {c["id"] for c in report0["claims"]}
    second = {c["id"] for c in report["claims"]}
    return {
        "original": ORIGINAL,
        "repeat": REPEAT,
        "source_journals": [src["journal_sha256"], dest["journal_sha256"]],
        "graded_mapping_sha256": sha256(mapping_path.read_bytes()).hexdigest(),
        "proposal_fingerprints": digests,
        "newly_retained": sorted(second - first),
        "newly_rejected": sorted(first - second),
        "scope": "One repeated Python sample. Only per-run evidence IDs normalized. All 30 texts, values, techniques, kinds, quote bytes, coordinates and claim IDs compared before reusing the development labels.",
        "after_filter": scoped_counts(
            score["after_filter"], {u["id"] for u in read(PROFILE)["units"]}
        ),
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    result = compare()
    output = EVIDENCE / "web-live-repeat-quality.json"
    if args.write:
        dump_json(output, result)
    elif read(output) != result:
        raise ValueError("Score differs from published repeat")
    print(
        result["newly_retained"], result["newly_rejected"], result["after_filter"]["f1"]
    )
