"""The public stability check must detect changed membership, inputs and evidence."""

import pytest

from eval import report_series


def test_stability_rejects_substituted_claim_key():
    series = report_series.read(report_series.PUBLIC)
    case = series["cases"][0]
    claim = next(c for c in case["decisions"] if c["retained"])
    claim["key"] = "0" * 64
    with pytest.raises(ValueError, match="terminal claim keys"):
        report_series.analyze(series)


def test_stability_rejects_configuration_drift(monkeypatch):
    series = report_series.read(report_series.PUBLIC)
    original = report_series.read
    target = series["cases"][1]["run"]

    def changed(path):
        row = original(path)
        if path.name == f"web-{target}.json":
            row["config_sha256_excluding_sample"] = "1" * 64
        return row

    monkeypatch.setattr(report_series, "read", changed)
    with pytest.raises(ValueError, match="configuration"):
        report_series.analyze(series)


def test_stability_rejects_duplicates_and_empty_sets_are_undefined():
    series = report_series.read(report_series.PUBLIC)
    series["cases"][2] = series["cases"][0]
    with pytest.raises(ValueError, match="distinct terminal"):
        report_series.analyze(series)
    assert report_series.overlap([set(), set(), set()])["rate"] is None


@pytest.mark.parametrize("mutation", ["omit", "duplicate", "score"])
def test_incomplete_attempt_cannot_be_hidden_or_scored(mutation):
    cohort = report_series.read(report_series.ARGUMENT_SERIES)
    base = cohort["series"]
    if mutation == "omit":
        base["attempts"].pop()
    elif mutation == "duplicate":
        base["attempts"][-1] = base["attempts"][1]
    else:
        base["claim_stability"] = {"stability": 1.0}
    with pytest.raises(ValueError, match="membership|fabricated"):
        report_series.analyze(cohort)


def test_distinguishes_new_proposals_from_changed_reviews():
    def row(id, key, signature, kept):
        return {"id": id, "key": key, "signature": signature, "kind": "behavior",
                "retained": kept, "atoms": []}
    a = row("C1", "a", "same", True)
    b = row("C2", "b", "one", True)
    cases = [{"decisions": [a, b]}, {"decisions": [dict(a, retained=False), dict(b, signature="two", retained=False)]},
             {"decisions": [a]}]
    first, second = report_series.changing_claims(cases)
    assert first["same_input_opposite_decisions"] and not first["absent_in_drafts"]
    assert second["absent_in_drafts"] and not second["same_input_opposite_decisions"]
    assert second["steps"][-1] == []


def test_type_scores_reproduce_the_whole_report_counts():
    old = report_series.read(report_series.PUBLIC)
    for c, expected in zip(old["cases"], old["summary"]["score_per_run"], strict=True):
        groups = report_series.kind_scores(c, report_series.read(report_series.PROFILE))
        for k in ("correct", "incorrect", "unsupported", "missed"):
            assert sum(g[k] for g in groups.values()) == expected[k]
