"""Source attribution for the argument in an exception handler."""
import pytest
from vm_tools.operation_dotnet import candidates
from stealer_agent.operation_assertions import render


def facts(body, declaration="catch (Exception err)", other=""):
    src = f"class App {{ {other} void Work() {{ try {{ Read(); }} {declaration} {{ {body} }} }} }}"
    return [f for f in candidates(src.encode()) if f["operation"] == "catch_message_argument"]


def test_handler_argument_can_be_bound_without_knowing_the_callee_effect():
    found, = facts('Record(); logger.Write("[" + err.Message + "]");', other="void Broken() { int n = ; }")
    assert found["inputs"] == {"variable": "err", "call": "logger.Write"}
    assert "sole argument" in render(found)


@pytest.mark.parametrize("body", [
    "logger.Write(other.Message);", "err = other; logger.Write(err.Message);",
    "Replace(out err); logger.Write(err.Message);", "logger.Write(err.Message + userData);",
    'logger.Write("credentials=" + err.Message);', "logger.Write(err.Message, other);",
    "logger.Write(label: err.Message);", "if (flag) { logger.Write(err.Message); }",
    "Action cb = () => logger.Write(err.Message);", "logger.Write(Wrap(err.Message));",
])
def test_missing_or_mixed_binding_is_omitted(body):
    assert not facts(body)


def test_filtered_handler_does_not_qualify():
    assert not facts("logger.Write(err.Message);", "catch (Exception err) when (Check(ref err))")


def test_only_the_complete_cited_handler_claim_is_excluded_from_verdict(tmp_path):
    from vm_tools.evidence import EvidenceStore
    from vm_tools.operation_facts import extract_operations
    from stealer_agent.operation_assertions import catalog, catch_context_ids

    digest = "a" * 64
    store = EvidenceStore(tmp_path)
    page = store.add(sample="demo.bin", sample_sha256=digest, tool="decompile_dotnet", backend="test",
                     text="class App { void M() { try { Work(); }\ncatch (Exception err) {\nlogger.Write(err.Message);\n} } }")
    eid = page["evidence_id"]
    record = store.get(eid, digest)
    evidence = {eid: {**record, "operation_facts": extract_operations(record)["facts"],
                       "line_map": {r["line"]:r["text"] for r in record["lines"]}}}
    entries, _ = catalog(evidence, digest)
    source, = entries
    claim = {"id": "C1", "text": source["text"], "evidence": source["evidence"]}
    other = {**claim, "id":"C2", "evidence": claim["evidence"][:1]}
    assert catch_context_ids(evidence, digest, [claim, other]) == ["C1"]
