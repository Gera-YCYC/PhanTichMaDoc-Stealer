"""Feedback must be linked to the original anchor and preserve its held-out split."""

from hashlib import sha256
import json
from pathlib import Path
import pytest
from lab_web.cases import ROOT
from stealer_agent.journal import canonical, dump_json
from training import build_web_dataset as feedback


def test_feedback_verifies_anchor_and_never_moves_sample_to_train(
    tmp_path, monkeypatch
):
    original = json.loads(
        (ROOT / "training/corpus/code-reference-v1.json").read_bytes()
    )
    row = next(r for r in original["rows"] if r["split"] == "test")
    anchor = {**row, "end": row["line"], "fact": "anchor_review"}
    monkeypatch.setattr(
        feedback,
        "case",
        lambda run: {
            "sha": row["sample_sha256"],
            "sample": row["sample"],
            "anchors": [anchor],
        },
    )
    sample = {
        k: row[k] for k in ("sample", "sample_sha256", "tool", "line", "output_sha256")
    }
    sample.update(
        schema=1,
        run="test-run",
        fact=anchor["fact"],
        label_origin="operator_ui",
        created="2026-01-01",
        judgment="supports",
        retrieval={k: row[k] for k in ("features", "query", "anchor_sha256")},
    )
    labels = tmp_path / "labels"

    def save(r):
        dump_json(labels / (sha256(canonical(r)).hexdigest() + ".json"), r)

    save(sample)
    output = tmp_path / "corpus.json"
    feedback.build(labels, output)
    revised = json.loads(output.read_bytes())
    match = next(r for r in revised["rows"] if r["id"] == row["id"])
    assert (
        revised["web_review_count"] == 1
        and match["split"] == "test"
        and match["label"] == 1
    )
    save({**sample, "judgment": "irrelevant"})
    with pytest.raises(ValueError, match="Conflicting"):
        feedback.build(labels, output)


def test_no_feedback_cannot_train_candidate(tmp_path):
    with pytest.raises(ValueError, match="No source-verified"):
        feedback.build(tmp_path, tmp_path / "output.json")
