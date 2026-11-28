"""Negative controls for source joins and for reusing a development grade."""

from copy import deepcopy

import pytest

from eval import transfer_report_audit as audit
from stealer_agent import flow_review as flow


def upload_case():
    rows = {
        10: 'string suffix = "/demo/file.txt?key=" + label;',
        11: "WebClient reader = new WebClient();",
        12: "try",
        13: "{",
        14: "byte[] result = reader.UploadFile(baseUri + suffix, inputFile);",
    }
    fact = {
        "operation": "file_upload",
        "api": "System.Net.WebClient.UploadFile(String,String)",
        "result": {"meaning": "response_body_bytes"},
        "inputs": {
            "address_expression": "baseUri + suffix",
            "file_path_expression": "inputFile",
        },
        "ranges": [{"line": n, "end_line": n} for n in (11, 14)],
    }
    return {"evidence_id": "test", "line_map": rows}, fact


def test_prefix_needs_a_bound_call():
    rec, fact = upload_case()
    prefix, ref = flow.upload_prefix(rec, fact)
    assert (prefix, ref["line"], ref["end_line"]) == ("/demo/file.txt?key=", 10, 14)


@pytest.mark.parametrize(
    ("line", "replacement"),
    [
        (10, 'string suffix = "/file.txt?key=secret" + label;'),
        (10, 'string suffix = "https://example.invalid/file.txt?key=" + label;'),
        (11, "WebClient another = new WebClient();"),
        (12, "suffix = newValue;"),
        (12, "[REDACTED-PRIVATE-FRAGMENT]"),
        (13, None),
        (14, "byte[] result = reader.UploadFile(other + suffix, inputFile);"),
        (14, "byte[] result = reader.UploadFile(baseUri + suffix, other);"),
        (14, "reader.UploadFile(baseUri + suffix, inputFile); next();"),
    ],
)
def test_ambiguous_or_incomplete_call_has_no_claim(line, replacement):
    rec, fact = upload_case()
    if replacement is None:
        del rec["line_map"][line]
    else:
        rec["line_map"][line] = replacement
    assert flow.upload_prefix(rec, fact) is None


def test_malformed_address_is_not_an_observation():
    rec, fact = upload_case()
    fact["inputs"]["address_expression"] = None
    assert flow.upload_prefix(rec, fact) is None


def test_message_edges_from_distinct_sources_do_not_compose(monkeypatch):
    roles = [
        "helper_attachment",
        "open_argument",
        "read_to_payload",
        "attach",
        "serialize",
    ]
    trail = [
        {"eid": "one", "line": n, "end": n, "role": role}
        for n, role in enumerate(roles, 1)
    ]
    send = [{"eid": "two", "line": n, "end": n} for n in (5, 6)]
    edges = [
        {"id": "archive-message", "status": "supported", "trail": trail},
        {"id": "message-send", "status": "supported", "refs": send},
    ]
    monkeypatch.setattr(flow, "ledger", lambda *_: {"edges": edges})
    records = {
        "one": {
            "evidence_id": "one",
            "line_map": {n: "local view" for n in range(1, 7)},
        }
    }
    assert [p["route"] for p in flow.candidates(records, "sample")] == [
        "attachment_payload"
    ]


def test_graded_coordinates_must_contain_the_frozen_witness():
    receipt = deepcopy(audit.read(audit.PUBLIC)["trial"])
    receipt["cases"][0]["rows"][0]["ranges"] = [[82, 82]]
    with pytest.raises(ValueError, match="reference coverage"):
        audit.audit(receipt)
