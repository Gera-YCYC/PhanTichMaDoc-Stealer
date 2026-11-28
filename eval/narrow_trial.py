"""Run the bounded recovery on all eligible card rejections in a fixed cohort."""

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256

from eval.web_report_quality import ROOT, read
from stealer_agent.card_journal import rejected_card_requests
from stealer_agent.journal import Journal, record_model_request, verify_journal
from stealer_agent.narrow_review import narrow
from stealer_agent.transport import OllamaClient

# Three original web samples, two .NET supplement runs, then an additional
# family from a past experiment. Freeze this selection before looking at outcomes.
COHORT = {
    "python": "20261128T021511_bec5b2e5",
    "gomorrah": "20261128T030521_c76fc69a",
    "mercurial": "20261128T031606_ca91de35",
    "gomorrah-extra": "20261128T034933_343e6946",
    "mercurial-extra": "20261128T035027_852cfb9f",
    "agenttesla": "20261128T003743_f8acf7f0",
}


def source(name, run):
    folder = (
        ROOT
        / ("private/report-experiments" if name.endswith("-extra") else "runs")
        / run
    )
    path = folder / "events.jsonl"
    verify_journal(path)
    events = [json.loads(s) for s in path.read_bytes().splitlines()]
    if events[-1]["event"] == "run_finished":
        saved = read(folder / "report.private.json")
        if events[-1]["result"] != saved:
            raise ValueError("Terminal run differs from report")
        model = saved["model"]["digest"]
    elif (
        events[0]["event"] == "replay_started"
        and events[-1]["event"] == "replay_finished"
    ):
        model = events[0]["model"]["digest"]
    else:
        raise ValueError("Incomplete run")
    return (
        sha256(path.read_bytes()).hexdigest(),
        model,
        list(rejected_card_requests(events)),
    )


def main(mode):
    config = ROOT / "config/host.investigation.example.json"
    client = OllamaClient(read(config))
    model = client.inspect()
    journal = Journal(
        ROOT / "private/narrow-trials" / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    )
    print(journal.directory.name, flush=True)
    journal.append(
        "trial_started",
        model=model,
        config_sha256=sha256(config.read_bytes()).hexdigest(),
        recovery_sha256=sha256(
            (ROOT / "stealer_agent/narrow_review.py").read_bytes()
        ).hexdigest(),
        cohort=COHORT,
        mode=mode,
    )
    step = 0
    counts = Counter()

    def invoke(messages, schema, phase, evidence):
        nonlocal step
        step += 1
        record_model_request(
            journal,
            step=step,
            phase=phase,
            messages=messages,
            schema=schema,
            evidence=evidence,
        )
        response, metrics = client.chat(messages, schema)
        journal.append(
            "model_response", step=step, phase=phase, response=response, metrics=metrics
        )
        return response

    for name, run in COHORT.items():
        digest, original_model, cases = source(name, run)
        if original_model != model["digest"]:
            raise ValueError("Different source model")
        journal.append(
            "source_bound",
            sample=name,
            run=run,
            journal_sha256=digest,
            parents=len(cases),
        )
        for c, check, req in cases:
            journal.append(
                "parent", run=run, claim=c["id"], request_sha256=req["messages_sha256"]
            )
            candidate, decision = narrow(c, check, req, invoke, mode=mode)
            journal.append(
                "outcome",
                run=run,
                parent=c["id"],
                candidate=candidate,
                decision=decision,
            )
            counts[decision] += 1
            print(name, c["id"], decision, flush=True)
    journal.append("trial_finished", calls=step, counts=dict(counts))
    verify_journal(journal.path)
    print(dict(counts), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("lines", "ranges"), default="ranges")
    main(parser.parse_args().mode)
