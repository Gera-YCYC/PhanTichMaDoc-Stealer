"""A retained assertion, its exact VM ranges and a positive operation decision are all required."""
from copy import deepcopy
import pytest

from stealer_agent.operation_assertions import catalog
from stealer_agent.send_recovery import SEND, recover
from stealer_agent.verdict_support import SUPPORT_KEYS
from test_operation_assertions import evidence


def inputs(tmp_path):
    records = evidence(tmp_path)
    item, = catalog(records, 'a' * 64)[0]
    claim = {"id": "C11", "text": item["text"], "evidence": item["evidence"], "kind": "behavior"}
    report = {"claims": [claim], "verdict_claim_ids": ["C1"], "verdict": "suspicious",
              "verdict_support": {k: [] for k in SUPPORT_KEYS}, "verdict_support_missing": list(SUPPORT_KEYS)}
    return records, report, {item["fact_id"]: claim["id"]}


@pytest.mark.parametrize("damage", ["no_review", "wrong_claim", "text", "quote", "range", "wrong_digest", "rejected"])
def test_nearby_send_is_not_a_reviewed_citation(tmp_path, damage):
    records, report, selected = inputs(tmp_path)
    claim = report["claims"][0]
    digest = "a" * 64
    if damage == "no_review":
        selected.clear()
    elif damage == "wrong_claim":
        selected[next(iter(selected))] = "C1"
    elif damage == "text":
        claim["text"] += " A password was sent."
    elif damage == "quote":
        claim["evidence"][0]["quote"] += "!"
    elif damage == "range":
        claim["evidence"] = claim["evidence"][-1:]
    elif damage == "wrong_digest":
        digest = "b" * 64
    else:
        report["claims"].clear()
    before = deepcopy(report)
    assert not recover(report, records, digest, selected)["sites"]
    assert report == before


def test_recovery_adds_only_the_static_send_and_preserves_prior_verdict(tmp_path):
    records, report, selected = inputs(tmp_path)
    receipt = recover(report, records, "a" * 64, selected)
    assert receipt["prior_citations"] == ["C1"]
    site, = receipt["sites"]
    assert site["refs"][-1]["line"] == 4 and site["claim"] == "C11"
    assert report["verdict_claim_ids"] == ["C1", "C11"]
    assert report["verdict"] == receipt["prior_verdict"] == "suspicious"
    assert report["verdict_support"] == {k: ["C11"] if k == SEND else [] for k in SUPPORT_KEYS}
    assert report["verdict_support_missing"] == [SUPPORT_KEYS[0], SUPPORT_KEYS[2]]


def test_full_verdict_keeps_original_citations_and_records_unallocated_site(tmp_path):
    records, report, selected = inputs(tmp_path)
    report["verdict_claim_ids"] = [f"C{i}" for i in range(1, 11)]
    before = deepcopy(report)
    site, = recover(report, records, "a" * 64, selected)["sites"]
    assert site["status"] == "citation_limit" and report == before


def test_reviewed_send_does_not_suppress_a_different_exact_site(tmp_path):
    records, report, selected = inputs(tmp_path)
    report["verdict_support"][SEND] = ["C1"]
    report["verdict_support_missing"].remove(SEND)
    assert recover(report, records, "a" * 64, selected)["sites"][0]["status"] == "recovered"
    assert report["verdict_support"][SEND] == ["C1", "C11"]
    assert recover(report, records, "a" * 64, selected)["sites"] == []
