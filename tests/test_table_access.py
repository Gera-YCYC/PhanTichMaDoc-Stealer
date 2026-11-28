"""Use inert C# text to check the two argument forms and lexical limits."""
import pytest

from stealer_agent.operation_assertions import render
from vm_tools.operation_dotnet import candidates
from lab_web.cases import reader_fields
from stealer_agent.journal import canonical
from hashlib import sha256


def fields(body):
    source = "class Example { void Run() { SQLite db = new SQLite(path); " + body + " } }"
    return [f for f in candidates(source.encode()) if f["operation"].startswith("reader_")]


def test_named_and_indexed_columns_remain_distinct():
    facts = fields('db.ReadTable("inventory"); for (int i = 0; i < count; i++) { db.GetValue(i, "sku"); db.GetValue(i, 2); }')
    assert [f["operation"] for f in facts] == ["reader_named_field", "reader_ordinal_field"]
    assert [f["inputs"] for f in facts] == [{"table": "inventory", "column": "sku"}, {"table": "inventory", "column": "2"}]
    assert "unresolved" in render(facts[1])


@pytest.mark.parametrize("body", [
    'if (flag) db.ReadTable("inventory"); db.GetValue(i, 2);',
    'db.ReadTable("inventory"); db = another; db.GetValue(i, 2);',
    'db.ReadTable("inventory"); Reset(out db); db.GetValue(i, 2);',
    'db.ReadTable("inventory"); db.ReadTable(dynamicName); db.GetValue(i, 2);',
    'db.ReadTable("inventory"); other.GetValue(i, 2);',
    'db.ReadTable("inventory"); System.Action a = () => db.GetValue(i, 2);',
    'db.ReadTable("inventory"); db.GetValue(i, expression);',
    'db.ReadTable("inventory"); db.GetValue(row: i, column: 2);',
])
def test_ambiguous_or_unbound_reads_are_omitted(body):
    assert fields(body) == []


def test_error_in_sibling_method_preserves_only_local_reader_sites():
    code = b'''using System.Net;
class Example {
 void Broken() { int n = ; }
 void Intact() {
    SQLite db = new SQLite(path);
    db.ReadTable("inventory");
    db.GetValue(i, 2);
    WebClient client = new WebClient();
    client.UploadFile(address, path);
 }
}'''
    facts = candidates(code)
    assert [f["operation"] for f in facts] == ["reader_ordinal_field"]
    assert facts[0]["source_ranges"] == [(5, 5), (6, 6), (7, 7)]
    assert not candidates(code.replace(b"db.GetValue(i, 2);", b"db.GetValue(i, 2); int x = ;"))
    assert not candidates(code[:-1])


def test_web_field_requires_observed_source_and_exact_retained_claim():
    raw = fields('db.ReadTable("inventory"); db.GetValue(i, "internal_field");')[0]
    raw.pop("source_ranges")
    record = {"evidence_id": "ev_f", "sample_sha256": "a" * 64, "output_sha256": "b" * 64}
    fact = {**record, **raw, "ranges": [{"line": 2, "end_line": 2}], "backend": "static-operation-facts/6"}
    fid = "op_" + sha256(canonical(fact)).hexdigest()[:16]
    record.update(line_map={2: 'db.GetValue(i, "internal_field");'}, operation_facts=[{**fact, "fact_id": fid}])
    ref = {"evidence_id": "ev_f", "line": 2, "end_line": 2, "quote": record["line_map"][2]}
    claim = {"id": "C2", "text": render(fact), "evidence": [ref]}
    row, = reader_fields(record, {fid: "C2"}, {"C2": claim})
    assert row["claim"] == "C2" and row["column"] is None and not row["ordinal"]
    row, = reader_fields(record, {fid: "C2"}, {"C2": {**claim, "evidence": []}})
    assert row["claim"] is None
    assert reader_fields({**record, "line_map": {}}, {}, {}) == []
