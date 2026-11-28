import json
from pathlib import Path

import pytest

from eval.supplement_review import audit
from lab_web.cases import cited_windows, trace_search
from scripts.replay_card_report import reconstruct


def test_trace_binds_to_step_and_counts_only_observed_anchors():
    attempts = {}
    trace_search(
        attempts,
        {
            "event": "hypothesis_open",
            "step": 4,
            "edge": "message-send",
            "query": "sendmail",
        },
    )
    projected = {
        "lines": [{"line": 7, "text": ""}],
        "search_groups": [{"anchor_line": 7}, {"anchor_line": 9}],
    }
    trace_search(
        attempts, {"event": "observation", "step": 3, "model_visible": projected}
    )
    assert not attempts[4]["anchors"]
    trace_search(
        attempts, {"event": "observation", "step": 4, "model_visible": projected}
    )
    result = {
        "event": "hypothesis_result",
        "step": 4,
        "edge": "process-write",
        "status": "partial",
        "hit_count": 2,
        "tool_status": "ok",
    }
    with pytest.raises(ValueError):
        trace_search(attempts, result)
    trace_search(attempts, {**result, "edge": "message-send"})
    assert attempts[4]["anchors"] == [7]
    assert attempts[4]["hits"] == 2 and attempts[4]["status"] == "partial"
    trace_search(
        attempts,
        {
            "event": "hypothesis_open",
            "step": 5,
            "edge": "message-send",
            "query": "as_string",
        },
    )
    assert attempts[5]["status"] is None
    assert not attempts[5]["anchors"]


def test_cited_window_preserves_coordinates_masks_literals_and_checks_source_digest():
    record = {
        "tool": "decompile_dotnet",
        "output_sha256": "a" * 64,
        "line_map": {3: 'field = "sensitive";', 4: "print(field)", 6: "return"},
    }
    refs = [
        {"eid": "ev_one", "line": 3, "end": 6},
        {"eid": "ev_one", "line": 4, "end": 4, "output_sha256": "b" * 64},
    ]
    graph = {"nodes": [], "edges": [{"refs": refs}]}
    windows = cited_windows({"ev_one": record}, graph, [])
    assert list(windows) == ["ev_one:3:6"]
    assert windows["ev_one:3:6"]["rows"] == [
        [3, 'field = "…";', True],
        [4, "print(field)", True],
        [6, "return", True],
    ]


def test_replay_keeps_search_fallback_and_navigation_anchor():
    eid = "ev_" + "0" * 16
    shown = {
        "evidence_id": eid,
        "lines": [{"line": 4, "text": "pass"}, {"line": 5, "text": "pass"}],
    }
    log = [
        {"event": "action_dispatched", "step": 3, "action": "search_evidence"},
        {"event": "observation", "step": 3, "model_visible": shown},
        {"event": "navigation_page_read", "evidence_id": eid, "anchor": 5},
    ]
    assert reconstruct(log)[eid]["focus_groups"] == [[4, 5], [5]]
    with pytest.raises(ValueError, match="anchor"):
        reconstruct([*log, {**log[-1], "anchor": 6}])


def test_public_review_keeps_negative_results_and_false_rejection():
    records = audit()
    assert sum(len(r["rows"]) for r in records.values()) == 10
    assert sum(r["metrics"]["model_calls"] for r in records.values()) == 17
    assert not any(r["new_accepted_units"] for r in records.values())
    good = records["mercurial"]["rows"][0]
    assert (good["label"], good["retained"], good["supported_units"]) == (
        "correct",
        False,
        ["native-decrypt"],
    )
    receipt = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "deliverables/real-demo-evidence/web-cng-review.json"
        ).read_bytes()
    )
    for row in receipt["rows"]:
        assert row["control"]["messages_sha256"] == row["original_request_sha256"]
    assert all(
        sum(r[arm]["supported"] == r["expected_support"] for r in receipt["rows"]) == 1
        for arm in ("control", "reference")
    )
