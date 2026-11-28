"""Static controls for the archive input path. These snippets are never executed."""

from copy import deepcopy

import pytest

from stealer_agent.investigation import ledger
from stealer_agent.staging_evidence import checked_path
from vm_tools.evidence import EvidenceStore
from vm_tools.operation_facts import extract_operations
from vm_tools.staging_link import find_witness


DOCUMENTS = """import shutil
base = "project"
groups = {"north": 1, "south": 2}
def labels():
    names = []
    for key, value in groups.items():
        if value:
            names.append(key)
    return names
def note():
    return "agenda"
def store(group, title, content):
    with open(base + f"/reports/{group}/{title}.txt", "w") as stream:
        stream.write(content)
def bundle():
    shutil.make_archive(base + "/output", "zip", base + "/reports")
def prepare():
    selected = labels()
    for group in selected:
        text = note()
        store(group, "meeting", text)
    finished = bundle()
"""


def inspect(tmp_path, code=DOCUMENTS, visible=None):
    store = EvidenceStore(tmp_path)
    page = store.add(
        sample="agenda.py",
        sample_sha256="c" * 64,
        tool="decompile_python",
        backend="test",
        text=code,
    )
    rec = store.get(page["evidence_id"], page["sample_sha256"])
    facts = extract_operations(rec)["facts"]
    lines = {r["line"]: r["text"] for r in rec["lines"]}
    witness = find_witness(rec, facts, set(lines) if visible is None else visible)
    return {**rec, "line_map": lines, "operation_facts": facts, "staging_link": witness}


def test_proves_lexical_child_while_archive_membership_remains_open(tmp_path):
    rec = inspect(tmp_path)
    path = checked_path(rec, rec["sample_sha256"])
    assert path["component_count"] == 2
    assert path["roles"]["write"] == 14
    graph = ledger({rec["evidence_id"]: rec}, rec["sample_sha256"])
    edge = next(e for e in graph["edges"] if e["id"] == "write-archive")
    assert edge["path_check"] == path
    assert edge["status"] == "partial"
    assert path["unresolved"] == "file_presence_at_archive_time"


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ('"/reports/{group}/', '"/reports-old/{group}/'),
        ('"/reports/{group}/', '"/reports/../other/{group}/'),
        ('"south": 2', '"../south": 2'),
        ('"south": 2', '"NUL": 2'),
        ('"south": 2', "external_name: 2"),
        ("groups.items():", "groups.items():\n        groups.update(other)"),
        (
            "selected = labels()",
            "selected = labels()\n    selected.append(external_name)",
        ),
        ("text = note()", "text = note()\n        group = other"),
        ("text = note()", "text = note()\n        text = other"),
        ('"meeting", text)', "external_name, text)"),
        ('"meeting", text)', '"meeting", unrelated)'),
        (
            "def store(group, title, content):",
            "def store(group, title, content):\n    title = external_name",
        ),
        ("stream.write(content)", "stream.write(other)"),
        ('f"/reports/{group}/', 'f"/reports/{group!r}/'),
        ('"zip", base + "/reports"', '"zip", another + "/reports"'),
        ("def labels():", "alias = groups\ndef labels():"),
        ("names.append(key)", "names.append(value)"),
        ("finished = bundle()", "if enabled:\n        finished = bundle()"),
        ("def note():", "def note():\n    global base"),
        (
            'shutil.make_archive(base + "/output", "zip", base + "/reports")',
            'unrelated(base + "/output", "zip", base + "/reports"); shutil.make_archive(base + "/output", "zip", base + "/other")',
        ),
    ],
)
def test_incomplete_ambiguous_or_outside_input_has_no_path_certificate(
    tmp_path, before, after
):
    assert before in DOCUMENTS
    assert inspect(tmp_path, DOCUMENTS.replace(before, after))["staging_link"] is None


def test_unrelated_search_does_not_enlarge_result(tmp_path):
    assert inspect(tmp_path, visible={1})["staging_link"] is None


def test_guarded_view_must_still_contain_all_certificate_rows(tmp_path):
    rec = inspect(tmp_path)
    assert checked_path(rec, rec["sample_sha256"])
    for change in ("removed", "masked", "different_hash", "different_sample"):
        copy = deepcopy(rec)
        first = copy["staging_link"]["lines"][0]
        if change == "removed":
            del copy["line_map"][first]
        elif change == "masked":
            copy["line_map"][first] = "[REDACTED-INJECTION]"
        elif change == "different_hash":
            copy["staging_link"]["component_count"] += 1
        else:
            copy["sample_sha256"] = "b" * 64
        assert checked_path(copy, rec["sample_sha256"]) is None
