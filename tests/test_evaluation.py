import importlib.util
from pathlib import Path
import pytest

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / "eval" / (name + ".py"))
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def test_lecturer_four_label_math():
    labels = ["correct"] * 8 + ["incorrect", "unsupported", "missed", "missed"]
    rows = [{"sample_sha256": "a"*64, "claim_key": str(i), "label": label,
             "grounded": label == "correct", "reviewer": "unit-test", "truth_reference": "synthetic-only"}
            for i, label in enumerate(labels)]
    metrics = module("score").calculate({"claims": rows, "verdicts": []})["metrics"]
    assert metrics["precision"] == .8 and metrics["recall"] == .8
    assert metrics["f1"] == pytest.approx(.8) and metrics["hallucination_rate"] == .1
    assert metrics["verdict_accuracy"] is None

def test_empty_evaluation_does_not_claim_zero_errors():
    result = module("score").calculate({"claims": [], "verdicts": []})
    assert all(value is None for value in result["metrics"].values())
    assert not result["teacher_dataset_complete"]

def test_stability_requires_three_runs_same_input():
    with pytest.raises(ValueError):
        module("stability").calculate([])

def test_empty_stability_is_undefined():
    value = {"sample_sha256": "a"*64, "model": {"digest": "b"*64},
             "status": "completed_needs_review", "analysis": {"claims": [], "verdict": "inconclusive"}}
    assert module("stability").calculate([value]*3)["stability"] is None
