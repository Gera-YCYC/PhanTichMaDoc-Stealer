"""Regressions for specific source bonds, the local web surface and blind review."""

import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import pytest

from lab_web.cases import directory, review_anchors
from lab_web.server import Handler
from lab_web.yara_view import regression
from lab_web.cases import ROOT
from eval.web_stability import compare_edges
from stealer_agent.indicator_candidates import candidates
from stealer_agent.investigation import ledger, options, proven_pair


def span(n):
    return {"line": n, "end_line": n}


def mime_pair(rows):
    a = {
        "operation": "mime_serialize",
        "result": {"assigned_expression": "body"},
        "ranges": [span(3)],
    }
    b = {
        "operation": "smtp_send",
        "inputs": {"message_expression": "body"},
        "ranges": [span(3 + len(rows) - 1)],
    }
    return proven_pair(a, b, {"line_map": dict(enumerate(rows, 3))})


def test_lexical_link_through_try_body():
    assert mime_pair(
        [
            "    body = msg.as_string()",
            "    try:",
            "        client.starttls()",
            "        client.sendmail(a,b,body)",
        ]
    )


@pytest.mark.parametrize(
    "middle",
    [
        "    body = another",
        "    if cond:",
        "    print(body)",
        "    body += x",
        None,
        "    [REDACTED-INJECTION]",
    ],
)
def test_link_requires_complete_unmodified_definition(middle):
    assert not mime_pair(
        ["    body = msg.as_string()", middle, "    client.sendmail(a,b,body)"]
    )


def test_role_specific_ioc():
    for text in [
        'fields.Add("avatar_url", (object)"https://image.invalid/logo");',
        'doc["ignored"] = {"icon_url": "https://image.invalid/a"}',
    ]:
        assert not candidates([{"quote": text, "line": 1, "evidence_id": "x"}])
    assert candidates(
        [
            {
                "quote": 'target = "https://api.invalid/submit"',
                "line": 4,
                "evidence_id": "x",
            }
        ]
    )


def test_literal_hint_cannot_prove_edge():
    evidence = {
        "ev": {
            "tool": "decompile_python",
            "status": "ok",
            "sample_sha256": "hash",
            "line_map": {5: "# sendmail", 7: 'name = "make_archive"'},
        }
    }
    graph = ledger(evidence, "hash")
    assert not any(e["status"] == "supported" for e in graph["edges"] + graph["nodes"])
    assert any(n["status"] == "partial" for n in graph["nodes"])
    assert not any(n["refs"] for n in ledger(evidence, "other")["nodes"])
    gap, queries = options(
        graph,
        {"sendmail", "uploadfile"},
        tool="decompile_python",
        record=evidence["ev"],
    )
    assert gap and not {"sendmail", "uploadfile"} & {q.casefold() for q in queries}


def test_missing_feature_neighbors_never_become_training_data():
    raw = {
        "lines": [{"line": 10, "text": "select()"}],
        "search_groups": [{"anchor_line": 10, "query": "select"}],
        "total_lines": 24,
    }
    assert list(review_anchors(raw, raw)) == []


def test_navigation_rejects_foreign_paths():
    for value in ["../config/lab.token", "private", "a/b", ""]:
        with pytest.raises(ValueError):
            directory(value)


def test_regression_compares_a_single_verified_clean_file_across_versions():
    result = regression(ROOT)
    assert result["before_fp"] == 1 and result["holdout_fp"] == 0
    assert result["before_clean"] == result["holdout_clean"] == 38
    assert len(result["changes"]) == 1
    change = result["changes"][0]
    assert change["matched_before"] and not change["matched_after"]
    assert change["sample"] == "clean_ytdlp_20240806.bin"


def test_missing_or_partial_agreement_does_not_raise_supported_link_stability():
    def graph(state):
        return {
            "edges": [{"id": "a", "status": state}, {"id": "b", "status": "partial"}]
        }

    partial = graph("partial")
    assert compare_edges([partial] * 3)["supported_intersection_over_union"] is None
    result = compare_edges([graph("supported"), graph("supported"), partial])
    assert result["same_state_all_three"] == 1
    assert result["supported_intersection_over_union"] == 0
    with pytest.raises(ValueError):
        compare_edges([partial, partial, {"edges": []}])


def test_web_rejects_cross_origin_and_unlisted_files():
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            c = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            c.request("GET", "/config/lab.token")
            assert c.getresponse().status == 404
            c.request("GET", "/api/init", headers={"Host": "elsewhere.invalid"})
            assert c.getresponse().status == 403
            c.request(
                "POST",
                "/api/analyze",
                body=b"{}",
                headers={"Origin": "http://elsewhere.invalid"},
            )
            assert c.getresponse().status == 403
        finally:
            server.shutdown()
            thread.join()
