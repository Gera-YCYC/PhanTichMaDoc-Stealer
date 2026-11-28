"""Compare the normal final report stage on three immutable development runs."""

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from uuid import uuid4

from eval.web_report_quality import EVIDENCE, ROOT, read
from lab_web.cases import records_for, trusted_report
from stealer_agent.evidence_cards import finalize_claims
from stealer_agent.flow_review import review
from stealer_agent.journal import (
    Journal,
    canonical,
    dump_json,
    record_model_request,
    verify_journal,
)
from stealer_agent.transport import OllamaClient


def checksum(path):
    return sha256(path.read_bytes()).hexdigest()


def run_trial():
    cfg = read(ROOT / "config/host.investigation.example.json")
    model = OllamaClient(cfg)
    digest = model.inspect()["digest"]
    trial = ROOT / "private/transfer-reports" / ("trial_" + uuid4().hex[:12])
    receipt = {
        "trial": trial.name,
        "model_digest": digest,
        "config_sha256": checksum(ROOT / "config/host.investigation.example.json"),
        "method_sha256": checksum(ROOT / "stealer_agent/flow_review.py"),
        "cases": [],
    }
    for donor in read(EVIDENCE / "web-current-batch.json")["runs"]:
        run = donor["run_id"]
        base = ROOT / "runs" / run
        parent = base / "events.jsonl"
        r = trusted_report(run)
        if (
            digest != r["model"]["digest"]
            or checksum(parent) != donor["journal"]["sha256"]
        ):
            raise ValueError("Different source run or model")
        ev = records_for(run)
        sample = r["sample_sha256"]
        original = read(base / "report.private.json")["analysis"]
        raw = read(base / "report.model-raw.json")
        old_claims = raw["claims"]
        old_final = [
            e
            for e in map(json.loads, parent.read_bytes().splitlines())
            if e.get("phase") == "card_verdict"
        ]
        if len(old_final) != 2:
            raise ValueError("Expected one original verdict")
        log = Journal(trial / run)
        log.append(
            "start",
            run=run,
            sample_sha256=sample,
            parent_sha256=checksum(parent),
            model_digest=digest,
            config_sha256=receipt["config_sha256"],
            method_sha256=receipt["method_sha256"],
        )

        def frozen(messages, schema, phase, exposure):
            req, res = old_final
            if (
                phase != "card_verdict"
                or req["messages"] != messages
                or req["schema"] != schema
                or req["evidence"] != exposure
                or req["phase"] != res["phase"]
            ):
                raise ValueError("Baseline synthesis request differs from original")
            return res["action"]

        _, baseline = finalize_claims(
            ev,
            sample,
            old_claims,
            original["claims"],
            original["rejected_claims"],
            frozen,
            log,
        )
        for k in (
            "claims",
            "rejected_claims",
            "verdict",
            "verdict_support",
            "verdict_claim_ids",
        ):
            if baseline[k] != original[k]:
                raise ValueError("Baseline failed exact replay for " + k)
        calls = []

        def invoke(messages, schema, phase, exposure):
            record_model_request(
                log,
                step=len(calls) + 1,
                phase=phase,
                messages=messages,
                schema=schema,
                evidence=exposure,
            )
            reply, usage = model.chat(messages, schema)
            log.append("model_response", phase=phase, action=reply, metrics=usage)
            calls.append(
                {
                    "phase": phase,
                    **{
                        k: usage[k]
                        for k in ("prompt_tokens", "completion_tokens", "latency_s")
                    },
                }
            )
            return reply

        claims, accepted, rejected = (
            deepcopy(old_claims),
            deepcopy(original["claims"]),
            deepcopy(original["rejected_claims"]),
        )
        review(ev, sample, invoke, log, claims, accepted, rejected)
        _, checked = finalize_claims(
            ev, sample, claims, accepted, rejected, invoke, log
        )
        if [
            c for c in checked["claims"] if c["id"] in {x["id"] for x in old_claims}
        ] != original["claims"]:
            raise ValueError("Previous accepted claims changed")
        log.append("finished", checked=checked)
        verify_journal(log.path)
        decisions = {
            e["claim_id"]: e["route"]
            for e in map(json.loads, log.path.read_bytes().splitlines())
            if e["event"] == "flow_review_decision"
        }
        rows = [
            {
                "id": c["id"],
                "route": decisions[c["id"]],
                "kind": c["kind"],
                "sha256": sha256(canonical(c)).hexdigest(),
                "retained": c in checked["claims"],
                "ranges": [[ref["line"], ref["end_line"]] for ref in c["evidence"]],
            }
            for c in claims[len(old_claims) :]
        ]
        receipt["cases"].append(
            {
                "run": run,
                "sample": r["sample"],
                "sample_sha256": sample,
                "parent_sha256": checksum(parent),
                "journal_sha256": checksum(log.path),
                "baseline_claims": len(original["claims"]),
                "retained": len(checked["claims"]),
                "verdict": checked["verdict"],
                "calls": calls,
                "rows": rows,
            }
        )
        print(run, len(rows), checked["verdict"], flush=True)
    dump_json(trial / "receipt.json", receipt)
    print(trial, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    run_trial()
