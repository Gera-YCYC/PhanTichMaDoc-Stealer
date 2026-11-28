import json
from hashlib import sha256

import pytest

from stealer_agent.journal import Journal, canonical, record_model_request
from stealer_agent.sample_binding import SampleBinding
from stealer_agent.demo_samples import CONTROL, registry
from eval import model_identity


def test_alias_is_scoped_to_actual_vm_file():
    binding = SampleBinding("clean_signed.bin")
    choice = {"sample": "case.bin", "query": "Send"}
    assert binding.vm_arguments(choice) == {"sample": "clean_signed.bin", "query": "Send"}
    assert choice["sample"] == "case.bin"
    assert SampleBinding("public_packaged.bin").alias == binding.alias
    assert SampleBinding("source.py").alias == "case.py"
    for alternate in ("clean_signed.bin", "public_packaged.bin", "../case.bin"):
        with pytest.raises(ValueError):
            binding.vm_arguments({"sample": alternate})


@pytest.mark.parametrize("field,phase,leak", [
    ("messages", "react", "Action rejected: CLEAN_SIGNED"),
    ("schema", "react", {"const": "clean_signed.bin"}),
    ("evidence", "card_verdict", "signed-clean-control-local-slm-vm"),
    ("messages", "legacy_semantic_review", "real-public-malware-local-slm-vm"),
])
def test_refuses_exposure_before_model_request(tmp_path, field, phase, leak):
    log = Journal(tmp_path / "run", sample_binding=SampleBinding("clean_signed.bin"))
    args = {"messages": [], "schema": {}, "evidence": []}
    with pytest.raises(RuntimeError, match=field):
        record_model_request(log, step=1, phase=phase, **{**args, field: leak})
    assert not log.path.exists()
    evidence = [{"text": "public static void Cleanup()"}]
    record_model_request(log, step=2, phase=phase, **{**args, "evidence": evidence})
    assert json.loads(log.path.read_bytes())["evidence"] == evidence


@pytest.mark.parametrize("mismatch", ["", "model", "vm", "digest", "leak"])
def test_audit_checks_identity_even_with_valid_journal_chain(tmp_path, monkeypatch, mismatch):
    """These small records test the verifier, independent of quality measurements."""
    run = "20260101T000000_abcdef12"
    folder = tmp_path / run
    monkeypatch.setattr(model_identity, "directory", lambda _: folder)
    log = Journal(folder)
    digest = registry(model_identity.ROOT)[CONTROL]["sha256"]
    log.append("run_started", sample=CONTROL,
               config={"neutral_sample_id":True, "expected_sample_sha256":digest})
    log.append("sample_binding", run=run, alias="case.bin", sample=CONTROL, expected_sha256=digest)
    source = {"module.py":"b"*64}
    log.append("source_version", files=source, manifest_sha256=sha256(canonical(source)).hexdigest())
    record_model_request(log, step=1, messages=[{"content":CONTROL if mismatch == "leak" else "case.bin"}],
                         schema={}, evidence=[])
    log.append("model_response", step=1, phase="react",
               action={"action":"identify", "arguments":{"sample":CONTROL if mismatch == "model" else "case.bin"}})
    log.append("action_dispatched", step=1, action="identify",
               arguments={"sample":"case.bin" if mismatch == "vm" else CONTROL})
    observation = {"sample":CONTROL, "sample_sha256":"0"*64 if mismatch == "digest" else digest}
    log.append("observation", step=1, raw=observation, model_visible=observation)
    log.append("run_finished", result={
        "run_id":run, "sample":CONTROL, "sample_sha256":digest, "model":{"digest":"a"*64},
        "status":"incomplete", "analysis":{"verdict":"inconclusive"},
        "metrics":{"model_calls":1, "tool_calls":1, "elapsed_s":1., "tool_errors":0},
    })
    if mismatch:
        with pytest.raises(ValueError):
            model_identity.audit(run)
    else:
        result = model_identity.audit(run)
        assert result["exposure"] == {"messages":0, "schema":0, "evidence":0}
        assert result["observations"] == result["dispatches"] == 1
