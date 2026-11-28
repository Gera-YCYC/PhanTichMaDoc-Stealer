from copy import deepcopy

import pytest

from stealer_agent.link_source import source_read
from stealer_agent.role_evidence import COLLECT, LINK
from vm_tools.evidence import EvidenceStore
from vm_tools.operation_facts import extract_operations


def observation(tmp_path):
    store = EvidenceStore(tmp_path / "ev")
    added = store.add(sample="notes.bin", sample_sha256="a"*64, tool="decompile_python", backend="fixture",
                      text="def display():\n    path = 'notes.txt'\n    with open(path, 'r') as inp:\n        return inp.read()")
    row = store.get(added["evidence_id"], "a"*64)
    row["line_map"] = {s["line"]: s["text"] for s in row["lines"]}
    row["operation_facts"] = extract_operations(row)["facts"]
    return row, {row["evidence_id"]: row}


def anchor(row, part, n):
    return {"eid":row["evidence_id"], "output_sha256":row["output_sha256"], "part":part, "line":n}


def test_read_site_or_a_reviewed_collection_at_the_same_origin(tmp_path):
    row, records = observation(tmp_path)
    link = {"claim":"C2", "role":LINK, "witnesses":[anchor(row, "sensitive_source", 4)]}
    assert source_read(link, [], records, "a"*64)["operation"] == "file_read"
    link["witnesses"] = [anchor(row, "sensitive_source", 2)]
    assert source_read(link, [], records, "a"*64) is None
    earlier = {"claim":"C1","role":COLLECT,"status":"supported_by_review",
               "witnesses":[anchor(row,"sensitive_source",2), anchor(row,"read",4)]}
    result = source_read(link,[earlier],records,"a"*64)
    assert (result["claim"],result["operation"],result["line"]) == ("C1","file_read",4)


@pytest.mark.parametrize("damage", ["other_origin","other_output","wrong_sample","not_accepted","changed_fact"])
def test_no_credit_with_a_stale_or_unrelated_read(tmp_path, damage):
    row, records = observation(tmp_path)
    origin = anchor(row,"sensitive_source",2)
    link = {"claim":"C2","role":LINK,"witnesses":[origin]}
    earlier = {"claim":"C1","role":COLLECT,"status":"supported_by_review",
               "witnesses":[deepcopy(origin),anchor(row,"read",4)]}
    digest = "a"*64
    if damage == "other_origin":
        earlier["witnesses"][0]["line"] = 3
    elif damage == "other_output":
        earlier["witnesses"][1]["output_sha256"] = "b"*64
    elif damage == "wrong_sample":
        digest = "b"*64
    elif damage == "not_accepted":
        earlier["status"] = "insufficient"
    else:
        for fact in row["operation_facts"]:
            fact["api"] = "unknown"
    assert source_read(link,[earlier],records,digest) is None


def test_read_from_another_vm_evidence_id_does_not_bind_to_the_origin(tmp_path):
    row, records = observation(tmp_path / "first")
    other, extra = observation(tmp_path / "second")
    assert other["evidence_id"] != row["evidence_id"]
    origin = anchor(row, "sensitive_source", 2)
    earlier = {"claim":"C1", "role":COLLECT, "status":"supported_by_review",
               "witnesses":[origin, anchor(other,"read",4)]}
    link = {"claim":"C2", "role":LINK, "witnesses":[origin]}
    assert source_read(link,[earlier],records | extra,"a"*64) is None
