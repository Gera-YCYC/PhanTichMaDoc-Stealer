"""Q&A citations must come from the new, guarded observation."""

import pytest

from lab_web import review
from lab_web.review import question_choices, search_excerpts


@pytest.mark.parametrize("edge,question", [("other", "Một câu hỏi"), ("rows-process", "Một câu hỏi khác")])
def test_map_question_must_match_an_edge_in_this_case(monkeypatch, edge, question):
    graph = {"edges": [{"id": "rows-process", "label": "Đọc → Xử lý"}], "nodes": []}
    monkeypatch.setattr(review, "case", lambda run: {"graph": graph})
    monkeypatch.setattr(review, "records_for", lambda run: {})
    with pytest.raises(ValueError, match="Đường nối"):
        review.answer({"run": "example", "question": question, "focus_edge": edge}, {}, None)


def test_directory_is_not_a_mail_stage_in_a_path_question():
    choices = question_choices("Đích ghi tệp có nằm trong thư mục nén không?", {})
    assert choices == ["write-archive"]
    assert question_choices("Bản nén có vào thư không?", {}) == ["archive-message"]


def test_search_cites_only_current_visible_matching_anchors():
    observation = {
        "evidence_id": "ev_example",
        "tool": "decompile_python",
        "output_sha256": "d" * 64,
        "search_query": "remove(",
        "lines": [
            {"line": 8, "text": "heading = 'meeting'"},
            {"line": 9, "text": "remove('internal-id')"},
            {"line": 10, "text": "[REDACTED-INJECTION]"},
        ],
        "search_groups": [
            {"query": "remove(", "anchor_line": 9, "lines": [8, 9, 10]},
            {"query": "remove(", "anchor_line": 10, "lines": [10]},
            {"query": "remove(", "anchor_line": 11, "lines": [11]},
            {"query": "unrelated", "anchor_line": 8, "lines": [8]},
            {"query": "remove(", "anchor_line": 9, "lines": [8, 9, 10]},
        ],
    }
    result = search_excerpts(observation)
    assert [ref["line"] for ref in result["refs"]] == [9]
    window = result["windows"]["ev_example:9:9"]
    assert window["output_sha256"] == observation["output_sha256"]
    assert [n for n, _, cited in window["rows"] if cited] == [9]
    assert "internal-id" not in str(result)


def test_empty_search_does_not_borrow_citations_from_the_report():
    assert search_excerpts(
        {
            "evidence_id": "ev_x",
            "tool": "decompile_python",
            "output_sha256": "e" * 64,
            "search_query": "remove(",
            "lines": [],
            "search_groups": [],
        }
    ) == {"refs": [], "windows": {}}
