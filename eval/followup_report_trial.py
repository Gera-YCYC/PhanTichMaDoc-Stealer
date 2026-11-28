"""Generate and review four real report extensions from the paired VM search log."""

import argparse
import json
from time import perf_counter
from uuid import uuid4

from eval.dotnet_followup import PUBLIC, fingerprint
from eval.web_report_quality import ROOT, read
from lab_web.cases import records_for
from scripts.replay_card_report import reconstruct
from stealer_agent.evidence_cards import create_card_report
from stealer_agent.followup_report import followup_cards
from stealer_agent.journal import Journal, record_model_request, verify_journal
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient


def sources():
    receipt = read(PUBLIC)
    path = ROOT / "private/dotnet-followups" / receipt["trial"] / "events.jsonl"
    verify_journal(path)
    if fingerprint(path) != receipt["journal_sha256"]:
        raise ValueError("Paired-search log differs from the published one")
    arms = {}
    for event in map(json.loads, path.read_bytes().splitlines()):
        if event["event"] == "case":
            sample = event["name"]
            parent = receipt["samples"][sample]
            if (
                fingerprint(ROOT / "runs" / parent["run"] / "events.jsonl")
                != parent["parent_sha256"]
            ):
                raise ValueError("Changed parent")
            (original,) = [
                r
                for r in records_for(parent["run"]).values()
                if r["tool"] == "decompile_dotnet"
            ]
            if original["output_sha256"] != event["output_sha256"]:
                raise ValueError("ILSpy output differs")
        if event["event"] == "search":
            obs = event["observation"]
            if (
                obs["output_sha256"] != original["output_sha256"]
                or obs["sample_sha256"] != original["sample_sha256"]
            ):
                raise ValueError("Search is not bound to the parent")
            key = (sample, event["mode"])
            observations, _ = arms.setdefault(key, ([], set(original["line_map"])))
            observations.append(obs)
    return receipt, arms


def prepare(queries, original):
    evidence = reconstruct(
        [{"event": "observation", "model_visible": obs} for obs in queries]
    )
    return evidence, followup_cards(evidence, queries, original)


def experiment():
    source, arms = sources()
    config = ROOT / "config/host.investigation.example.json"
    model = OllamaClient(read(config))
    meta = model.inspect()
    if meta["digest"] != source["model_digest"]:
        raise ValueError("Model differs from original agent")
    folder = ROOT / "private/followup-reports" / ("reports_" + uuid4().hex[:12])
    print(folder.name, flush=True)
    for (sample, mode), (queries, original) in arms.items():
        evidence, cards = prepare(queries, original)
        journal = Journal(folder / sample / mode)
        journal.append(
            "start",
            source=source["journal_sha256"],
            model=meta["digest"],
            sample=sample,
            mode=mode,
            config_sha256=fingerprint(config),
            selector_sha256=fingerprint(ROOT / "stealer_agent/followup_report.py"),
            reporter_sha256=fingerprint(ROOT / "stealer_agent/evidence_cards.py"),
        )
        calls = 0

        def invoke(messages, schema, phase, exposed):
            nonlocal calls
            free = available_memory_bytes()
            if free is not None and free < 256 * 1024 * 1024:
                raise RuntimeError("Too little RAM to continue report generation")
            calls += 1
            record_model_request(
                journal,
                step=calls,
                messages=messages,
                schema=schema,
                phase=phase,
                evidence=exposed,
            )
            response, usage = model.chat(messages, schema)
            journal.append(
                "model_response",
                step=calls,
                phase=phase,
                response=response,
                metrics=usage,
            )
            return response

        start = perf_counter()
        raw, checked = create_card_report(
            evidence,
            queries[0]["sample_sha256"],
            invoke,
            journal,
            max_cards=4,
            card_selector=lambda *args, **kwargs: cards,
        )
        journal.append(
            "finished",
            raw=raw,
            checked=checked,
            seconds=round(perf_counter() - start, 3),
            calls=calls,
        )
        verify_journal(journal.path)
        print(
            sample,
            mode,
            len(cards),
            len(raw["claims"]),
            len(checked["claims"]),
            calls,
            flush=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", required=True)
    parser.parse_args()
    experiment()
