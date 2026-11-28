"""Read-only source checks on a fictional telemetry database."""
from copy import deepcopy
from hashlib import sha256

import pytest

from stealer_agent.flow_review import candidates
from stealer_agent.investigation import checked_argument, ledger
from stealer_agent.journal import canonical
from vm_tools.evidence import EvidenceStore
from vm_tools.operation_facts import extract_operations
from vm_tools.row_use import find_witness


SOURCE = '''import sqlite3
from Crypto.Cipher import AES
def inspect_block(block, key, nonce):
    payload = block
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    result = cipher.decrypt(payload)
    return result
def inspect_series(key, nonce):
    db = sqlite3.connect(":memory:")
    cur = db.cursor()
    cur.execute("SELECT sample_id, measurement FROM readings")
    for row in cur.fetchall():
        result = inspect_block(row[1], key, nonce)
'''


def record(tmp_path, text=SOURCE, visible=(12,)):
    store = EvidenceStore(tmp_path)
    digest = sha256(text.encode()).hexdigest()
    page = store.add(sample="telemetry.py", sample_sha256=digest, tool="decompile_python",
                     backend="test", text=text)
    rec = store.get(page["evidence_id"], digest)
    facts = extract_operations(rec)["facts"]
    return {**rec, "line_map": {r["line"]: r["text"] for r in rec["lines"]},
            "operation_facts": facts, "row_use": find_witness(rec, facts, visible)}


@pytest.mark.parametrize(("index", "column"), [(0, "sample_id"), (1, "measurement")])
def test_uses_actual_column_and_source_coordinates(tmp_path, index, column):
    rec = record(tmp_path, SOURCE.replace("row[1]", f"row[{index}]"))
    digest = rec["sample_sha256"]
    check = checked_argument(rec, digest)
    assert check and (check["index"], check["position"], check["column"]) == (index, 0, column)
    assert check["roles"] == {"query": 11, "rows": 12, "argument": 13, "parameter": 3, "operation": 6}
    records = {rec["evidence_id"]: rec}
    edge = next(e for e in ledger(records, digest)["edges"] if e["id"] == "rows-process")
    assert edge["status"] == "supported" and edge["argument_check"] == check
    proposal, = [c for c in candidates(records, digest) if c["route"] == "selected_column_to_helper"]
    assert column in proposal["text"]
    assert [(r["line"], r["end_line"]) for r in proposal["evidence"]] == [
        (r["line"], r["end"]) for r in check["refs"]]


@pytest.mark.parametrize(("before", "after"), [
    ("row[1]", "row[-1]"), ("row[1]", "row[2]"), ("row[1]", "row[True]"),
    ("sample_id, measurement", "*"), ("sample_id, measurement", "sample_id AS x, measurement"),
    ("result = inspect_block(", "row = other\n        result = inspect_block("),
    ("result = inspect_block(", "if enabled:\n            result = inspect_block("),
    ("def inspect_series(key, nonce):", "def inspect_series(key, nonce, inspect_block):"),
    ("payload = block", "payload = unrelated"), ("cipher.decrypt(payload)", "cipher.decrypt(nonce)"),
    ("result = cipher.decrypt", "payload = unrelated\n    result = cipher.decrypt"),
    ("cur.fetchall()", "other.fetchall()"),
    ("result = cipher.decrypt(payload)", "a = nonce; result = cipher.decrypt(payload)"),
    ("def inspect_series(key, nonce):", "def configure(db):\n    db.row_factory = different\ndef inspect_series(key, nonce):"),
])
def test_abstains_when_the_join_is_ambiguous_or_broken(tmp_path, before, after):
    assert before in SOURCE
    assert record(tmp_path, SOURCE.replace(before, after), range(1, 20))["row_use"] is None


def test_requires_anchor_and_integrity_of_every_cited_row(tmp_path):
    assert record(tmp_path, visible=(2,))["row_use"] is None
    rec = record(tmp_path)
    for change in ("window", "missing", "sample", "output", "proof"):
        item = deepcopy(rec)
        if change == "window":
            item["line_map"][4] += " # changed"
        elif change == "missing":
            del item["line_map"][4]
        elif change == "sample":
            item["sample_sha256"] = "f" * 64
        elif change == "output":
            item["output_sha256"] = "f" * 64
        else:
            item["row_use"]["index"] += 1
        assert checked_argument(item, rec["sample_sha256"]) is None


def test_signed_but_non_text_column_is_invalid(tmp_path):
    rec = record(tmp_path)
    proof = rec["row_use"]
    proof["column"] = None
    body = {k: v for k, v in proof.items() if k != "proof_id"}
    proof["proof_id"] = "arg_" + sha256(canonical(body)).hexdigest()[:16]
    assert checked_argument(rec, rec["sample_sha256"]) is None
