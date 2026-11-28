"""Join operator-reviewed search anchors to the numeric, sample-disjoint ranker corpus."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
from lab_web.cases import ROOT, case, read
from stealer_agent.journal import canonical, dump_json


def build(folder, output):
    data = read(ROOT / "training/corpus/code-reference-v1.json")
    rows = data["rows"]
    splits = {r["sample_sha256"]: r["split"] for r in rows}
    key = lambda r: (r["output_sha256"], r["line"], r["query"])
    indexed = {key(r): r for r in rows}
    verified = {}
    for p in folder.glob("*.json"):
        r = read(p)
        if (
            sha256(canonical(r)).hexdigest() != p.stem
            or r.get("label_origin") != "operator_ui"
            or r.get("schema") != 1
        ):
            raise ValueError("Invalid label receipt")
        if "retrieval" not in r:
            continue
        # Source reports are verified against their terminal journals. Never turn
        # an SLM judgment into a human label, and never move a test sample to train.
        stored = case(r["run"])
        actual = next((x for x in stored["anchors"] if x["fact"] == r["fact"]), None)
        if (
            not actual
            or stored["sha"] != r["sample_sha256"]
            or stored["sample"] != r["sample"]
            or any(
                actual[k] != r["retrieval"][k]
                for k in ("query", "features", "anchor_sha256")
            )
            or any(actual[k] != r[k] for k in ("output_sha256", "line", "tool"))
        ):
            raise ValueError("Feedback source no longer matches the verified run")
        if r["sample_sha256"] not in splits:
            raise ValueError(
                "Assign a sample-disjoint split to the new sample before including its labels"
            )
        item = {
            k: r[k]
            for k in ("sample", "sample_sha256", "tool", "output_sha256", "line")
        }
        item.update(
            r["retrieval"],
            label=int(r["judgment"] == "supports"),
            split=splits[r["sample_sha256"]],
            label_origin="operator_ui_source_linked",
            feedback_sha256=p.stem,
        )
        i = key(item)
        if i in verified and verified[i][1]["label"] != item["label"]:
            raise ValueError(
                "Conflicting feedback for an anchor; reconcile labels before training"
            )
        verified[i] = max(
            [verified.get(i, ("", {})), (r["created"], item)], key=lambda pair: pair[0]
        )
    if not verified:
        raise ValueError("No source-verified operator search labels yet")
    for k, (_, item) in sorted(verified.items()):
        existing = indexed.get(k)
        if existing and (
            existing["features"] != item["features"]
            or existing["anchor_sha256"] != item["anchor_sha256"]
        ):
            raise ValueError("Feature or source revision mismatch")
        item["id"] = (
            existing["id"] if existing else "web_" + item["feedback_sha256"][:16]
        )
        indexed[k] = item
    data.update(
        rows=list(indexed.values()),
        web_review_count=len(verified),
        label_version=2,
        parent_dataset_sha256=sha256(
            (ROOT / "training/corpus/code-reference-v1.json").read_bytes()
        ).hexdigest(),
    )
    dump_json(output, data)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "--output", type=Path, default=ROOT / "private/web-ranker/corpus.json"
    )
    args = p.parse_args()
    build(ROOT / "evidence/local/web-feedback", args.output)
