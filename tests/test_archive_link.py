"""A local document attachment, with no network or collection capability. Parse only."""

import pytest
from vm_tools.archive_link import find_witness
from vm_tools.evidence import EvidenceStore
from vm_tools.operation_facts import extract_operations

SOURCE = """import shutil
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
def bundle(folder):
    path = folder + ".zip"
    shutil.make_archive(folder, "zip", folder)
    return path
def draft(attachment_path):
    msg = MIMEMultipart()
    with open(attachment_path, "rb") as stream:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(stream.read())
    msg.attach(part)
    text = msg.as_string()
def workflow(folder):
    chosen = bundle(folder)
    draft(chosen)
"""


def analyze(tmp_path, code, visible=None):
    store = EvidenceStore(tmp_path)
    page = store.add(
        sample="document.txt",
        sample_sha256="a" * 64,
        tool="decompile_python",
        backend="test",
        text=code,
    )
    record = store.get(page["evidence_id"], page["sample_sha256"])
    facts = extract_operations(record)["facts"]
    return find_witness(
        record, facts, visible if visible is not None else set(range(1, 30))
    )


def test_trace_requires_argument_and_attachment(tmp_path):
    w = analyze(tmp_path, SOURCE)
    assert w and w["kind"] == "archive-message"
    assert len(w["roles"]) == 11 and "text" not in w
    assert not analyze(tmp_path, SOURCE, set())


@pytest.mark.parametrize(
    "before,after",
    [
        ("return path", "return folder"),
        ("draft(chosen)", 'draft("another.zip")'),
        ("draft(chosen)", 'chosen = "another.zip"\n    draft(chosen)'),
        ('folder + ".zip"', 'folder + ".txt"'),
        ("part.set_payload(stream.read())", 'part.set_payload("alternate")'),
        ("msg.attach(part)", "msg.attach(another_part)"),
        ("with open(attachment_path", 'with open("another.zip"'),
        ("return path", "drop(path)\n    return path"),
    ],
)
def test_disconnected_paths_abstain(tmp_path, before, after):
    assert not analyze(tmp_path, SOURCE.replace(before, after))
