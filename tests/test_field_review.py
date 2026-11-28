import pytest

from lab_web.field_review import menu, review_rows
from stealer_agent.journal import Journal
from vm_tools.evidence import EvidenceStore
from vm_tools.field_call import inspect


SOURCE = """class Notebook {
    public void Record(int count) { }
}
class Desk {
    Notebook book = new Notebook();
    void Log() {
        book.Record(3);
    }
}
"""


def inspect_source(tmp_path, source):
    n = next(
        i for i, line in enumerate(source.splitlines(), 1) if "book.Record(" in line
    )
    store = EvidenceStore(tmp_path)
    page = store.add(
        sample="example",
        sample_sha256="a" * 64,
        tool="decompile_dotnet",
        backend="inert",
        text=source,
    )
    record = store.get(page["evidence_id"], page["sample_sha256"])
    result = inspect(record, n)
    assert all(row == record["lines"][row["line"] - 1] for row in result["lines"])
    return result


def test_explicit_field_navigation(tmp_path):
    result = inspect_source(tmp_path, SOURCE)
    assert result["ranges"] == {"call": [7, 7], "field": [5, 5], "method": [2, 2]}
    assert result["status"] == "source_candidate"


@pytest.mark.parametrize(
    "before,after",
    [
        ("void Log()", "void Log(Notebook book)"),
        ("book.Record(3);", "book = new Notebook(); book.Record(3);"),
        ("book.Record(3)", "book.Record(3, 5)"),
        ("new Notebook()", "new Ledger()"),
        ("public void Record", "public virtual void Record"),
        ("public void Record", "public void Record(string a) { } public void Record"),
        ("class Notebook", "partial class Notebook"),
        ("class Notebook {", "class Notebook : Ledger {"),
        (
            "public void Record(int count) { }",
            "public void Record(int count) {\n" + "\n" * 42 + "}",
        ),
    ],
)
def test_ambiguous_or_oversized_method_is_withheld(tmp_path, before, after):
    result = inspect_source(tmp_path, SOURCE.replace(before, after))
    assert result["status"] == "unresolved"
    assert not result["ranges"] and len(result["lines"]) == 1


def test_choices_use_distinct_observed_receivers():
    windows = {
        "a": {
            "rows": [
                [3, "x.Go(2);", True],
                [4, "x.Go(3);", False],
                [5, "y.Go(1);", False],
                [6, "⟦dòng đã ẩn⟧", True],
            ]
        }
    }
    assert menu(windows) == {3: "x.Go(2);", 5: "y.Go(1);"}


def test_qwen_cannot_cite_an_unobserved_row(tmp_path):
    class Client:
        def chat(self, messages, schema):
            return {"file_read": 3, "http_io": 2}, {}

    with pytest.raises(ValueError, match="Qwen"):
        review_rows(
            Client(), Journal(tmp_path / "journal"), "call", {2: "book.Record(2);"}, 1
        )
