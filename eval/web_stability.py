"""Score three real runs of the same configuration using their terminal reports."""

import argparse
from pathlib import Path

from lab_web.cases import ROOT, directory, read
from scripts.compare_demo_batch import compare
from stealer_agent.journal import dump_json


def compare_edges(graphs):
    if len(graphs) != 3:
        raise ValueError("Expected three terminal graphs")
    by_run = [{e["id"]: e["status"] for e in g["edges"]} for g in graphs]
    ids = set(by_run[0])
    if any(set(row) != ids for row in by_run):
        raise ValueError("Expected three graphs with the same declared edges")
    compared = {k: [row[k] for row in by_run] for k in sorted(ids)}
    supported = [{k for k, v in row.items() if v == "supported"} for row in by_run]
    common, union = set.intersection(*supported), set.union(*supported)
    return {
        "statuses_by_edge": compared,
        "same_state_all_three": sum(
            len(set(states)) == 1 for states in compared.values()
        ),
        "edge_count": len(ids),
        "supported_all_three": sorted(common),
        "supported_at_least_once": sorted(union),
        "supported_intersection_over_union": len(common) / len(union)
        if union
        else None,
    }


def evaluate(ids):
    if len(set(ids)) != 3 or len(ids) != 3:
        raise ValueError("Supply three distinct run IDs")
    batch = compare(ids)
    series = batch["stable_series_by_sample"]
    if len(series) != 1:
        raise ValueError("Three completed runs of one sample are required")
    reports = [read(directory(i) / "report.private.json") for i in ids]
    rows = batch["runs"]
    return {
        "runs": ids,
        "sample": rows[0]["sample"],
        "sample_sha256": rows[0]["sample_sha256"],
        "model_digest": rows[0]["model"]["digest"],
        "source_manifest_sha256": rows[0]["source_manifest_sha256"],
        "configuration_sha256": rows[0]["config_sha256_excluding_sample"],
        "journal_sha256": [r["journal"]["sha256"] for r in rows],
        "claim_stability": next(iter(series.values())),
        "verdicts": [r["analysis"]["verdict"] for r in reports],
        "web_graph": compare_edges([r["investigation"] for r in reports]),
        "accepted_claim_counts": [len(r["analysis"]["claims"]) for r in reports],
        "duration_seconds": [r["metrics"]["elapsed_s"] for r in reports],
        "tool_calls": [r["metrics"]["tool_calls"] for r in reports],
        "model_calls": [r["metrics"]["model_calls"] for r in reports],
        "scope": "One development sample, three terminal runs. Repeated edge status and exact accepted claim agreement are distinct measures. Neither measures correctness.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runs", nargs=3)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "evidence/local/web-stability.json"
    )
    args = parser.parse_args()
    result = evaluate(args.runs)
    dump_json(args.output, result)
    print(result["claim_stability"])
