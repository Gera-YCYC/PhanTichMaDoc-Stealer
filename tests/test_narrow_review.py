from hashlib import sha256

import pytest

from eval.narrow_audit import audit
from lab_web.cases import display_claim, recent_reviews
from stealer_agent.journal import Journal
from stealer_agent.narrow_review import select_refs


def test_ranges_cannot_cross_evidence_gaps_or_masked_rows():
    refs = [
        {"evidence_id": "source", "line": 3, "end_line": 4, "quote": "a\nb"},
        {
            "evidence_id": "source",
            "line": 6,
            "end_line": 6,
            "quote": "[REDACTED-INJECTION]",
        },
    ]
    assert select_refs(refs, [{"start": 4, "end": 4}])[0]["quote"] == "b"
    for a, b in [(3, 6), (6, 6), (4, 3), (2, 3)]:
        assert select_refs(refs, [{"start": a, "end": b}]) == []
    assert not select_refs(
        refs + [dict(refs[0], evidence_id="another")], [{"start": 3, "end": 3}]
    )


def test_rejected_quotes_require_actual_projected_text():
    c = {
        "id": "C3",
        "text": "Example",
        "evidence": [
            {"evidence_id": "s", "line": 1, "end_line": 1, "quote": "other()"}
        ],
    }
    records = {"s": {"line_map": {1: "value()"}}}
    assert display_claim(c, records, rejected=True)["refs"] == []
    c["evidence"][0]["quote"] = "value()"
    assert display_claim(c, records, rejected=True)["refs"][0]["line"] == 1


def test_only_finished_reviews_of_same_source_reopen(tmp_path):
    (tmp_path / "events.jsonl").write_bytes(b"source")
    d = sha256(b"source").hexdigest()
    j = Journal(tmp_path / "claim-reviews" / "review_test")
    j.append(
        "review_started",
        run="original",
        parent="C1",
        sample_sha256="s",
        model_digest="m",
        source_journal_sha256=d,
    )
    assert not recent_reviews(tmp_path, "original", "s", "m")
    j.append("review_finished", display={"claim": "C1", "id": "review_test"})
    assert not recent_reviews(tmp_path, "original", "s", "other")
    assert recent_reviews(tmp_path, "original", "s", "m")["C1"]["id"] == "review_test"
    (tmp_path / "events.jsonl").write_bytes(b"different")
    with pytest.raises(ValueError):
        recent_reviews(tmp_path, "original", "s", "m")


def test_fully_graded_public_experiment_does_not_confuse_approval_and_correctness():
    arms = audit()
    assert arms["ranges"]["summary"]["reviewed"] == 6
    lines = arms["lines"]["summary"]
    assert (
        lines["eligible"],
        lines["accepted"],
        lines["accepted_correct"],
        lines["accepted_unsupported"],
    ) == (13, 7, 2, 5)
