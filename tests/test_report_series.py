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
