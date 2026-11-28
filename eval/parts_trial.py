"""Run or reconstruct split review for all disputed behaviors in three frozen reports."""

import argparse
from datetime import UTC, datetime
from hashlib import sha256
import json

from eval.narrow_trial import source
from eval.web_report_quality import ROOT, read
from stealer_agent.claim_parts import split_review
from stealer_agent.journal import Journal, canonical, record_model_request, verify_journal
from stealer_agent.transport import OllamaClient

COHORT = {
    "python": "20261128T073934_730537f9",
    "gomorrah": "20261128T030521_c76fc69a",
    "mercurial": "20261128T031606_ca91de35",
}
TRIALS = ROOT / "private/parts-trials"
CONFIG = ROOT / "config/host.investigation.example.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def compare(bound_model, invoke, emit):
    for sample, run in COHORT.items():
        digest, model, cases = source(sample, run)
        require(model == bound_model, "Model differs from parent")
        emit("source", run=run, journal_sha256=digest, sample=sample, count=len(cases))
        for parent, _, req in cases:
            emit("parent", run=run, claim=parent["id"], request_sha256=req["messages_sha256"])
            parts = split_review(parent, req["evidence"][0]["tool"], invoke)
            emit("parts", run=run, parent=parent["id"], results=parts)


def method_hash():
    return sha256((ROOT / "stealer_agent/claim_parts.py").read_bytes()).hexdigest()


def run_live():
    client = OllamaClient(read(CONFIG))
    model = client.inspect()
    journal = Journal(TRIALS / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ"))
    journal.append("trial_started", model=model["digest"], cohort=COHORT,
                   config=sha256(CONFIG.read_bytes()).hexdigest(), method=method_hash())
    print(journal.directory.name, flush=True)
    steps = 0

    def invoke(messages, schema, phase, evidence):
        nonlocal steps
        steps += 1
        record_model_request(journal, step=steps, messages=messages, schema=schema,
                             phase=phase, evidence=evidence)
        answer, usage = client.chat(messages, schema)
        journal.append("model_response", step=steps, phase=phase, response=answer, metrics=usage)
        return answer

    try:
        compare(model["digest"], invoke, journal.append)
        journal.append("finished", calls=steps)
        verify_journal(journal.path)
        print("Model calls:", steps)
    except Exception as exc:
        journal.append("failed", error=type(exc).__name__)
        raise


def replay(path):
    verify_journal(path)
    events = iter(json.loads(line) for line in path.read_bytes().splitlines())

    def take(kind, **fields):
        event = next(events)
        require(event["event"] == kind and all(event[k] == v for k, v in fields.items()),
                "Different event or evidence in " + kind)
        return event

    start = take("trial_started", cohort=COHORT, method=method_hash())
    calls = 0
    token_in = token_out = 0
    seconds = 0.0
    rows = []

    def invoke(messages, schema, phase, evidence):
        nonlocal calls, token_in, token_out, seconds
        calls += 1
        take("model_request", messages=messages, schema=schema, phase=phase,
             evidence=evidence, step=calls, messages_sha256=sha256(canonical(messages)).hexdigest())
        response = take("model_response", phase=phase, step=calls)
        usage = response["metrics"]
        token_in += usage["prompt_tokens"]
        token_out += usage["completion_tokens"]
        seconds += usage["latency_s"]
        return response["response"]

    def emit(kind, **fields):
        take(kind, **fields)
        if kind == "parent":
            rows.append({"run": fields["run"], "parent": fields["claim"],
                         "parent_request_sha256": fields["request_sha256"], "parts": []})
        elif kind == "parts":
            for part in fields["results"]:
                claim = part["claim"]
                rows[-1]["parts"].append({
                    "fingerprint": sha256(canonical(claim)).hexdigest(),
                    "kept": part["check"]["supported"],
                    "ranges": [[r["line"], r["end_line"]] for r in claim["evidence"]],
                })

    compare(start["model"], invoke, emit)
    take("finished", calls=calls)
    require(next(events, None) is None, "Extra trial events")
    return {"trial": path.parent.name, "journal_sha256": sha256(path.read_bytes()).hexdigest(),
            "model_digest": start["model"], "method_sha256": start["method"],
            "config_sha256": start["config"], "parents": rows, "calls": calls,
            "input_tokens": token_in, "output_tokens": token_out, "inference_s": round(seconds, 3)}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--replay", metavar="TRIAL")
    args = cli.parse_args()
    if args.replay:
        result = replay(TRIALS / args.replay / "events.jsonl")
        print(json.dumps(result, indent=2))
    else:
        run_live()
