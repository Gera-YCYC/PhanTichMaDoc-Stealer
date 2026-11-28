"""Append-only per-run evidence, with timestamps and a hash chain."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def dump_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def record_model_request(journal, *, step, messages, schema, evidence, phase='react', **details):
    """Log the exact projected inputs, not a reconstruction from earlier pages.

    These are private request artifacts. Refuse an oversized request rather than
    claim an incomplete/truncated log proves exposure to a complete payload.
    """
    body={'messages':messages,'schema':schema,'evidence':evidence}
    if len(canonical(body)) > 512_000:
        raise ValueError('Model request provenance exceeds 512000-byte bound')
    return journal.append('model_request',step=step,phase=phase,**body,
                          messages_sha256=hashlib.sha256(canonical(messages)).hexdigest(),
                          schema_sha256=hashlib.sha256(canonical(schema)).hexdigest(),
                          scope='Exact messages/schema and projected evidence for next model call; private, not public export',
                          **details)


class Journal:
    def __init__(self, directory: Path, live: bool = False):
        directory.mkdir(parents=True, exist_ok=False)
        self.directory = directory
        self.path = directory / "events.jsonl"
        self.previous = "0" * 64
        self.sequence = 0
        self.live = live

    def append(self, event: str, **details) -> dict:
        self.sequence += 1
        payload = {"sequence": self.sequence, "timestamp": utc_now(), "event": event,
                   "previous_sha256": self.previous, **details}
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        payload["sha256"] = digest
        with self.path.open("a", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(payload, ensure_ascii=False) + "\n")
            output.flush()
            os.fsync(output.fileno())
        self.previous = digest
        if self.live:
            if event == 'run_started':
                print(f"[RUN] {details['sample']} | {self.directory.resolve()}", flush=True)
            elif event == 'preflight':
                print(f"[READY] Local model: {details['model']['tag']} | isolated VM: ready", flush=True)
            elif event == 'action_dispatched':
                print(f"[STEP {details['step']}] CALL {details['action']}", flush=True)
            elif event == 'hypothesis_open':
                print(f"[GAP {details['step']}] {details['edge']}", flush=True)
            elif event == 'observation':
                result=details['raw']
                print(f"[STEP {details['step']}] {result['tool']} -> {result['status']} | backend={result['backend']}",flush=True)
            elif event == 'python_fallback_required':
                print('[LIMIT] pycdc failed. Inspecting bytecode with pycdas remains possible; source recovery is incomplete.',flush=True)
            elif event == 'action_rejected':
                print(f"[STEP {details['step']}] Controller rejected an invalid action; details retained in the private journal",flush=True)
            elif event == 'run_error':
                print('[ERROR] Run stopped; see the local report for details',flush=True)
            elif event == 'evidence_cards_selected':
                print(f"[REPORT] {len(details['cards'])} bounded code excerpts selected", flush=True)
            elif event == 'card_claim_proposed':
                print(f"[REPORT] {details['card_id']} -> {details['claim']['id']} proposed; checking evidence", flush=True)
            elif event == 'card_claim_review':
                print(f"[REVIEW] {details['claim_id']} supported={details['check']['supported']} (same-model heuristic)", flush=True)
            elif event == 'run_finished':
                r=details['result']
                print(f"[DONE] {r['status']} | successful tools={len(r['successful_tools'])} | verdict={r['analysis']['verdict']}",flush=True)
        return payload


def verify_journal(path: Path) -> int:
    previous = "0" * 64
    count = 0
    for count, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = json.loads(line)
        expected = value.pop("sha256")
        if value["sequence"] != count or value["previous_sha256"] != previous:
            raise ValueError("Journal chain/sequence mismatch")
        if hashlib.sha256(canonical(value)).hexdigest() != expected:
            raise ValueError("Journal digest mismatch")
        previous = expected
    return count
