"""Keep the public web evaluation reproducible even on a clone without the lab."""

from copy import deepcopy

import pytest

from eval import web_report_quality as quality


def test_every_web_claim_and_omission_survives_publication():
    cohort = quality.reports()
    assert [len(run["rows"]) for run in cohort] == [30, 30, 39]
    for run in cohort:
        assert len(run["missed"]) == run["after_filter"]["missed"]
        assert run["after_filter"]["cited"] == sum(
            bool(row["lines"]) and row["retained"] for row in run["rows"]
        )
    last = {row["id"]: row for row in cohort[-1]["rows"]}
    assert (last["C16"]["label"], last["C16"]["retained"]) == ("correct", False)
    assert (last["C12"]["label"], last["C12"]["retained"]) == ("incorrect", True)


def test_a_repeated_run_cannot_count_as_three(monkeypatch):
    original = quality.read

    def repeat(path):
        data = original(path)
        if path.name == "web-stability-python.json":
            data = deepcopy(data)
            data["runs"][1] = data["runs"][0]
        return data

    monkeypatch.setattr(quality, "read", repeat)
    with pytest.raises(ValueError, match="distinct terminal runs"):
        quality.reports()


def test_cross_format_batch_counts_samples_once_and_preserves_verdicts():
    group = quality.current_batch()
    runs = {item["run_id"] for item in group["cases"]}
    graded = [
        quality.reports()[0],
        quality.reports(sample="gomorrah")[0],
        quality.reports(sample="mercurial")[0],
    ]
    assert runs == {r["run"] for r in graded}
    assert (group["total_attempts"], group["correct_verdicts"]) == (3, 0)
    for stage in ("raw", "after_filter"):
        summary = group[stage]["declared_units"]
        for name in ("correct", "incorrect", "unsupported", "missed"):
            assert summary[name] == sum(r[stage][name] for r in graded)
        assert summary["correct"] + summary["missed"] == 97
