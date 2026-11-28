"""Paired review of the Windows CNG claims on archived, projected VM evidence."""

import argparse
import json
import re
from copy import deepcopy
from datetime import UTC, datetime
from hashlib import sha256

from jsonschema import validate

from eval.web_report_quality import EVIDENCE, ROOT, read
from stealer_agent.journal import (
    Journal,
    canonical,
    dump_json,
    record_model_request,
    verify_journal,
)
from stealer_agent.transport import OllamaClient

DOC = "https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/"
SOURCES = [
    DOC + page
    for page in (
        "nf-bcrypt-bcryptdecrypt",
        "ns-bcrypt-bcrypt_authenticated_cipher_mode_info",
        "nf-bcrypt-bcryptopenalgorithmprovider",
        "nf-bcrypt-bcryptsetproperty",
    )
]
NOTES = (
    "\nOffline Windows CNG API reference. Evaluate the cited source bindings. "
    "BCryptOpenAlgorithmProvider selects an algorithm and provider. "
    "A chaining mode can be set separately using BCryptSetProperty. "
    "BCryptDecrypt takes a key handle and input buffer. For authenticated modes "
    "its padding-info argument may carry BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO "
    "with a nonce and an authentication tag. A call with a null output buffer "
    "can query the required size. Distinguish function arguments, wrapper "
    "arguments, and execution outcomes. API semantics alone do not establish "
    "which algorithm, mode, values or return status this excerpt demonstrates."
)

BASE = "20261128T031606_ca91de35"
EXTRA = "20261128T035027_852cfb9f"


def reviews(folder):
    path = folder / "events.jsonl"
    verify_journal(path)
    journal = [json.loads(s) for s in path.read_bytes().splitlines()]
    pending = None
    for event in journal:
        if event["event"] == "model_request" and event["phase"] == "card_review":
            pending = event
        elif event["event"] == "card_claim_review":
            if pending is None:
                raise ValueError("Missing original reviewer request")
            if "BCrypt" in json.loads(pending["messages"][-1]["content"])["code"]:
                yield event["claim_id"], pending, event["check"]["supported"]
            pending = None


def verify_published():
    receipt = read(EVIDENCE / "web-cng-review.json")
    if not re.fullmatch(r"\d{8}T\d{12}Z", receipt["trial"]):
        raise ValueError("Invalid trial identifier")
    path = ROOT / "private/review-trials" / receipt["trial"] / "events.jsonl"
    verify_journal(path)
    log = [json.loads(s) for s in path.read_bytes().splitlines()]
    if (
        sha256(path.read_bytes()).hexdigest() != receipt["journal_sha256"]
        or sha256(NOTES.encode()).hexdigest() != receipt["notes_sha256"]
        or log[0]["model"]["digest"] != receipt["model_digest"]
        or log[0]["config_sha256"] != receipt["config_sha256"]
        or log[0]["treatment"] != NOTES
        or log[0]["sources"] != receipt["sources"]
        or log[-1]["event"] != "paired_review_finished"
    ):
        raise ValueError("Published receipt differs from trial")
    grouped = {
        r: {cid: (req, prev) for cid, req, prev in reviews(parent / r)}
        for r, parent in [
            (BASE, ROOT / "runs"),
            (EXTRA, ROOT / "private/report-experiments"),
        ]
    }
    by_step = {e["step"]: e for e in log if e["event"] == "paired_review_response"}
    expected = {
        (r["run"], r["claim"], arm): (r, r[arm])
        for r in receipt["rows"]
        for arm in ("control", "reference")
    }
    for e in (e for e in log if e["event"] == "model_request"):
        row, arm = expected.pop((e["source_run"], e["claim"], e["arm"]))
        source, previous = grouped[e["source_run"]][e["claim"]]
        messages = deepcopy(source["messages"])
        if e["arm"] == "reference":
            messages[0]["content"] += NOTES
        result = by_step.pop(e["step"])
        if (
            source["messages_sha256"] != row["original_request_sha256"]
            or previous != row["original_support"]
            or messages != e["messages"]
            or e["schema"] != source["schema"]
            or e["evidence"] != source["evidence"]
            or e["messages_sha256"] != arm["messages_sha256"]
            or result["response"]["supported"] != arm["supported"]
            or any(
                result["usage"][key] != arm[key]
                for key in ("latency_s", "prompt_tokens", "completion_tokens")
            )
        ):
            raise ValueError("Paired input or outcome differs")
    if expected or by_step:
        raise ValueError("Missing request or extra response")
    print(
        "Verified both arms against six recorded responses and their exact original inputs"
    )


def main():
    config = ROOT / "config/host.investigation.example.json"
    client = OllamaClient(read(config))
    model = client.inspect()
    baseline = read(EVIDENCE / f"web-{BASE}.json")
    if model["digest"] != baseline["model_digest"]:
        raise ValueError("Model digest differs from original")
    cases = []
    # Include every reviewer request citing BCrypt in both selected journals.
    for run, parent, expected_hash in [
        (BASE, ROOT / "runs", baseline["journal_sha256"]),
        (
            EXTRA,
            ROOT / "private/report-experiments",
            "54dacbd6bac92bf325d942bf1f38dd8d0aebb07737e32a971b28773fa7b555ca",
        ),
    ]:
        folder = parent / run
        if sha256((folder / "events.jsonl").read_bytes()).hexdigest() != expected_hash:
            raise ValueError("Source journal changed")
        cases.extend((run, *r) for r in reviews(folder))
    labels = {(BASE, "C17"): False, (BASE, "C18"): True, (EXTRA, "C1"): True}
    if [(r, c) for r, c, _, _ in cases] != list(labels):
        raise ValueError("Different case selection")
    journal = Journal(
        ROOT / "private/review-trials" / datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    )
    config_hash = sha256(config.read_bytes()).hexdigest()
    journal.append(
        "paired_review_started",
        model=model,
        config_sha256=config_hash,
        sources=SOURCES,
        treatment=NOTES,
        case_labels=[(r, c, v) for (r, c), v in labels.items()],
    )
    rows = []
    for index, (run, claim, req, previous) in enumerate(cases):
        row = {
            "run": run,
            "claim": claim,
            "expected_support": labels[run, claim],
            "original_support": previous,
            "original_request_sha256": req["messages_sha256"],
        }
        order = ("control", "reference") if index % 2 == 0 else ("reference", "control")
        for step, arm in enumerate(order, start=index * 2 + 1):
            messages = deepcopy(req["messages"])
            if sha256(canonical(messages)).hexdigest() != req["messages_sha256"]:
                raise ValueError("Original prompt mismatch")
            if arm == "reference":
                messages[0]["content"] += NOTES
            logged = record_model_request(
                journal,
                step=step,
                phase="paired_review",
                messages=messages,
                schema=req["schema"],
                evidence=req["evidence"],
                arm=arm,
                source_run=run,
                source_step=req["step"],
                claim=claim,
            )
            result, usage = client.chat(messages, req["schema"])
            validate(result, req["schema"])
            journal.append(
                "paired_review_response", step=step, response=result, usage=usage
            )
            row[arm] = {
                "supported": result["supported"],
                "messages_sha256": logged["messages_sha256"],
                **{
                    k: usage[k]
                    for k in ("prompt_tokens", "completion_tokens", "latency_s")
                },
            }
            print(run, claim, arm, result["supported"], flush=True)
        rows.append(row)
    journal.append("paired_review_finished", cases=len(rows))
    verify_journal(journal.path)
    receipt = {
        "scope": "Paired development review on one .NET sample, same projected source and schema.",
        "model_digest": model["digest"],
        "config_sha256": config_hash,
        "sources": SOURCES,
        "notes_sha256": sha256(NOTES.encode()).hexdigest(),
        "trial": journal.directory.name,
        "journal_sha256": sha256(journal.path.read_bytes()).hexdigest(),
        "rows": rows,
    }
    dump_json(journal.directory / "receipt.json", receipt)
    print(journal.directory / "receipt.json")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--verify",
        action="store_true",
        help="Check the published trial locally without loading a model",
    )
    if p.parse_args().verify:
        verify_published()
    else:
        main()
