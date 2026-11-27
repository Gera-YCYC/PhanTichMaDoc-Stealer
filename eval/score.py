"""Grade independently adjudicated claims using the lecturer's four labels.

This does not ask an LLM to invent ground truth or treat tests as accuracy.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

LABELS = {"correct", "incorrect", "unsupported", "missed"}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def calculate(data: dict) -> dict:
    rows = data["claims"]
    seen = set()
    for row in rows:
        key = (row["sample_sha256"], row["claim_key"])
        if key in seen or row["label"] not in LABELS:
            raise ValueError("Duplicate claim or invalid lecturer label")
        seen.add(key)
        if not row.get("reviewer") or not row.get("truth_reference"):
            raise ValueError("Every adjudication requires a reviewer and ground-truth reference")
        if row["label"] == "correct" and row.get("grounded") is not True:
            raise ValueError("Correct claims must have verified supporting evidence")
    counts = {label: sum(r["label"] == label for r in rows) for label in LABELS}
    predicted = counts["correct"] + counts["incorrect"] + counts["unsupported"]
    precision = ratio(counts["correct"], predicted)
    recall = ratio(counts["correct"], counts["correct"] + counts["missed"])
    f1 = (2 * precision * recall / (precision + recall) if precision + recall else 0) \
        if precision is not None and recall is not None else None
    cases = data.get("verdicts", [])
    for case in cases:
        if case.get("expected") not in ("benign", "malicious") or not case.get("truth_reference"):
            raise ValueError("Verdict truth must be independently supplied")
    metrics = {"precision": precision, "recall": recall, "f1": f1,
               "hallucination_rate": ratio(counts["unsupported"], predicted),
               "grounding_rate": ratio(sum(r.get("grounded") is True for r in rows if r["label"] != "missed"), predicted),
               "verdict_accuracy": ratio(sum(c["predicted"] == c["expected"] for c in cases), len(cases))}
    return {"counts": counts, "metrics": metrics, "dataset_origin": data.get("dataset_origin", "unspecified"),
            "sample_count": len({r["sample_sha256"] for r in rows}),
            "teacher_dataset_complete": data.get("teacher_dataset_complete") is True,
            "acceptance": "requires full dataset coverage and separate runtime/safety evidence"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("adjudications")
    parser.add_argument("--output", default="evaluation.json")
    args = parser.parse_args()
    result = calculate(json.loads(Path(args.adjudications).read_text(encoding="utf-8")))
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
