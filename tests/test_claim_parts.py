"""Only rows supporting the individual assertion may reach its model reviewer."""

import json

from stealer_agent.claim_parts import split_review
from stealer_agent.slice_review import slice_discrepancy


def test_each_part_review_uses_its_own_rows():
    claim = {"id": "C2", "kind": "behavior", "text": "Copies a value and converts its type.",
             "value": "", "technique_id": "", "evidence": [{
                 "evidence_id": "ev_0123456789abcdef", "line": 10, "end_line": 12,
                 "quote": "entry = read()\nvalue = entry\nsave(value)",
             }]}
    phases = []

    def invoke(messages, schema, phase, evidence):
        phases.append(phase)
        if phase == "parts_propose":
            return {"parts": [
                {"text": "Assigns entry to value.", "lines": [11]},
                {"text": "Converts the result to a string.", "lines": [10, 12]},
            ]}
        rows = [r["line"] for r in evidence[0]["lines"]]
        payload = json.loads(messages[-1]["content"])
        if rows == [11]:
            assert "read()" not in payload["source"] and "save(" not in payload["source"]
            return {"supported": True, "reason": "Direct assignment."}
        assert rows == [10, 12] and "value = entry" not in payload["source"]
        return {"supported": False, "reason": "No type conversion is cited."}

    decisions = split_review(claim, "python_ast", invoke)
    assert phases == ["parts_propose", "parts_verify", "parts_verify"]
    assert [p["check"]["supported"] for p in decisions] == [True, False]
    assert claim["evidence"][0]["line"] == 10


def test_disallowed_or_unavailable_lines_cannot_enter_a_part():
    claim = {"id": "C1", "kind": "behavior", "text": "Tests a value.", "value": "",
             "technique_id": "", "evidence": [{"evidence_id": "ev_0123456789abcdef",
             "line": 2, "end_line": 2, "quote": "[REDACTED-INJECTION]"}]}
    for n in [2, 3]:
        def invoke(messages, schema, phase, evidence):
            assert phase == "parts_propose"
            return {"parts": [{"text": "Stores a value.", "lines": [n]}]}

        assert split_review(claim, "python_ast", invoke) == []


def test_prefix_discrepancy_requires_same_subject_and_one_literal_python_slice():
    claim = {"text": "The code extracts the tag from the first 8 bytes of the input.",
             "evidence": [{"line": 10, "end_line": 10, "quote": "tag = data[2:10]"}]}
    assert slice_discrepancy(claim, "python_ast") == {
        "line": 10, "start": 2, "stop": 10, "claimed_prefix": 8,
    }
    assert slice_discrepancy(claim, "decompile_dotnet") is None
    for quote in ("tag = data[2:6]", "other = data[2:10]", "tag = data[i:10]",
                  "tag = data[2:10:2]", "tag = data[2:10]; tag = another"):
        claim["evidence"][0]["quote"] = quote
        assert slice_discrepancy(claim, "python_ast") is None
