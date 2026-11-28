"""Fit a candidate with verified operator labels; compare with the frozen deployed ranker."""

from hashlib import sha256
import json
from uuid import uuid4
from .build_web_dataset import build
from .train_ranker import metrics, train
from lab_web.cases import ROOT, read
from stealer_agent.journal import dump_json


def main():
    out = ROOT / "private/web-ranker" / uuid4().hex
    dataset = out / "corpus.json"
    build(ROOT / "evidence/local/web-feedback", dataset)
    data = read(dataset)
    if not any(r["split"] == "train" and "feedback_sha256" in r for r in data["rows"]):
        raise ValueError(
            "No operator-reviewed training anchor. Validation and test labels cannot update weights."
        )
    w, b, loss = train(data, 300, 0.3, 0.01)
    frozen = read(ROOT / "vm_tools/code_ranker.json")
    compare = {}
    for split in ("train", "validation", "test"):
        rows = [r for r in data["rows"] if r["split"] == split]
        compare[split] = {
            "before": metrics(rows, frozen["weights"], frozen["bias"]),
            "after": metrics(rows, w, b),
        }
    dump_json(
        out / "candidate.json",
        {
            "weights": w,
            "bias": b,
            "features": data["features"],
            "feature_version": data["feature_version"],
        },
    )
    dump_json(out / "loss.json", loss)
    dump_json(
        out / "receipt.json",
        {
            "corpus_sha256": sha256(dataset.read_bytes()).hexdigest(),
            "reviewed": data["web_review_count"],
            "model": "auxiliary logistic retrieval ranker",
            "qwen_weights_updated": False,
            "deployed": False,
            "epochs": 300,
            "lr": 0.3,
            "l2": 0.01,
            "scores": compare,
        },
    )
    print(out / "receipt.json")


if __name__ == "__main__":
    main()
