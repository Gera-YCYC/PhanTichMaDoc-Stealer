import pytest
from hashlib import sha256

from eval.followup_report_audit import counted
from lab_web.dotnet_supplement import latest
from stealer_agent.journal import Journal

from stealer_agent.followup_report import followup_cards


def test_returned_lines_must_be_new_and_same_source():
    rows = {1: "public void ReadCount()", 2: "{", 3: "    count = CountRows();", 4: "}"}
    record = {
        "status": "ok",
        "tool": "decompile_dotnet",
        "evidence_id": "one",
        "sample_sha256": "sample",
        "output_sha256": "output",
        "line_map": rows,
    }
    query = {**record, "search_groups": [{"anchor_line": 3, "lines": list(rows)}]}
    assert followup_cards({"one": record}, [query], rows) == []
    cards = followup_cards({"one": record}, [query, query], {1, 2})
    assert len(cards) == 1 and cards[0]["reference"]["quote"] == "\n".join(
        rows.values()
    )
    with pytest.raises(ValueError):
        followup_cards({"one": record}, [{**query, "output_sha256": "different"}], {})


def test_supplement_counts_only_kept_unique_atoms_including_mixed_claims():
    base = {
        "matched_reference_ids": ["old"],
        "reference_units": 4,
        "incorrect": 0,
        "unsupported": 1,
    }
    rows = [
        {
            "retained": True,
            "hits": ["new"],
            "errors": ["unverified/again", "wrong/different"],
        },
        {"retained": True, "hits": ["old", "new"], "errors": ["wrong/different"]},
        {"retained": False, "hits": ["missing"], "errors": []},
    ]
    score = counted(base, rows, {"unverified/again"})
    assert (
        score["correct"],
        score["missed"],
        score["incorrect"],
        score["unsupported"],
    ) == (2, 2, 1, 1)
    assert score["precision"] == score["recall"] == score["f1"] == 0.5


def test_partial_or_different_parent_cannot_reopen(tmp_path):
    parent = tmp_path / "events.jsonl"
    parent.write_bytes(b"original")
    j = Journal(tmp_path / "supplements" / "extra_test")
    j.append(
        "start",
        run="r",
        sample_sha256="s",
        model="m",
        parent_sha256=sha256(parent.read_bytes()).hexdigest(),
    )
    assert latest(tmp_path, "r", "s", "m") is None
    j.append("supplement_finished", display={"id": "extra_test"})
    assert latest(tmp_path, "r", "s", "m")["id"] == "extra_test"
    parent.write_bytes(b"changed")
    with pytest.raises(ValueError):
        latest(tmp_path, "r", "s", "m")
