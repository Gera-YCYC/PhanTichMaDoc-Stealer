"""Reproduce each narrowing decision from the logged model replies, with no inference."""

import argparse
import json
from collections import Counter
from datetime import datetime
from hashlib import sha256

from eval.narrow_trial import COHORT, source
from eval.web_report_quality import EVIDENCE, ROOT, read
from stealer_agent.journal import canonical, dump_json, verify_journal
from stealer_agent.narrow_review import narrow

TRIALS = {
    "ranges": (
        "20261128T041624713463Z",
        "cebfca245a3f78fe56dbb44c6c7168dd4d37527f892f567a7ff2ff6b6c103536",
    ),
    "lines": (
        "20261128T042002566101Z",
        "a31731930c1271cae8be4b488c14d822ef2e61a2781df41d1df87f56f27e36e9",
    ),
}
LABELS = ROOT / "eval/adjudications/narrow-claims.json"
PUBLIC = EVIDENCE / "web-narrow-review.json"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def reproduce(mode, labels):
    trial, digest = TRIALS[mode]
    path = ROOT / "private/narrow-trials" / trial / "events.jsonl"
    verify_journal(path)
    require(sha256(path.read_bytes()).hexdigest() == digest, "Different trial journal")
    events = iter(json.loads(s) for s in path.read_bytes().splitlines())

    def take(kind):
        event = next(events)
        require(event["event"] == kind, "Unexpected event in " + trial)
        return event

    start = take("trial_started")
    require(
        start["cohort"] == COHORT and start.get("mode", "ranges") == mode,
        "Different cohort or mode",
    )
    resources = Counter()
    phases = Counter()
    rows = []
    source_hashes = {}
    used = set()

    def reply(messages, schema, phase, evidence):
        request = take("model_request")
        response = take("model_response")
        require(
            request["step"] == response["step"] == sum(phases.values()) + 1
            and request["phase"] == response["phase"] == phase
            and request["messages"] == messages
            and request["evidence"] == evidence
            and request["schema"] == schema
            and request["messages_sha256"] == sha256(canonical(messages)).hexdigest(),
            "Model inputs differ from original",
        )
        phases[phase] += 1
        for key in ("prompt_tokens", "completion_tokens"):
            resources[key] += response["metrics"][key]
        return response["response"]

    for name, run in COHORT.items():
        bound = take("source_bound")
        sha, model, parents = source(name, run)
        require(
            (bound["sample"], bound["run"], bound["journal_sha256"], bound["parents"])
            == (name, run, sha, len(parents))
            and start["model"]["digest"] == model,
            "Unbound parent report",
        )
        source_hashes[run] = sha
        for c, check, request in parents:
            parent = take("parent")
            require(
                (parent["run"], parent["claim"], parent["request_sha256"])
                == (run, c["id"], request["messages_sha256"]),
                "Wrong rejected claim",
            )
            candidate, decision = narrow(c, check, request, reply, mode=mode)
            end = take("outcome")
            require(
                (end["run"], end["parent"], end["candidate"], end["decision"])
                == (run, c["id"], candidate, decision),
                "Recovery result differs",
            )
            row = {
                "sample": name,
                "run": run,
                "parent": c["id"],
                "decision": decision,
                "parent_request_sha256": request["messages_sha256"],
                "ranges": [],
            }
            if candidate is not None:
                key = name + "/" + c["id"]
                label, statement, reason = labels[key]
                used.add(key)
                row.update(
                    label=label,
                    summary=statement,
                    reason=reason,
                    claim_sha256=sha256(canonical(candidate)).hexdigest(),
                    ranges=[[r["line"], r["end_line"]] for r in candidate["evidence"]],
                )
            rows.append(row)
    finish = take("trial_finished")
    totals = Counter(r["decision"] for r in rows)
    require(
        used == set(labels)
        and totals == finish["counts"]
        and finish["calls"] == sum(phases.values())
        and next(events, None) is None,
        "Incomplete source grades or run",
    )
    return {
        "trial": trial,
        "journal_sha256": digest,
        "model_digest": start["model"]["digest"],
        "measured_source_sha256": start["recovery_sha256"],
        "config_sha256": start["config_sha256"],
        "source_journals": source_hashes,
        "calls": dict(phases),
        "tokens": dict(resources),
        "elapsed_s": round(
            (
                datetime.fromisoformat(finish["timestamp"])
                - datetime.fromisoformat(start["timestamp"])
            ).total_seconds(),
            3,
        ),
        "rows": rows,
    }


def audit(replay=False, write=False):
    labels = read(LABELS)
    stored = {} if write else read(PUBLIC)
    final = {}
    for mode, (trial, sha) in TRIALS.items():
        arm = reproduce(mode, labels[mode]) if replay else stored[mode]
        require(
            arm["trial"] == trial and arm["journal_sha256"] == sha,
            "Mismatched published arm",
        )
        received = {
            r["sample"] + "/" + r["parent"]: [r["label"], r["summary"], r["reason"]]
            for r in arm["rows"]
            if r["ranges"]
        }
        require(
            received == labels[mode]
            and len({(r["run"], r["parent"]) for r in arm["rows"]}) == len(arm["rows"])
            and all(COHORT[r["sample"]] == r["run"] for r in arm["rows"]),
            "Unexpected case or grade",
        )
        kept = [r for r in arm["rows"] if r["decision"] == "accepted"]
        summary = {
            "eligible": len(arm["rows"]),
            "reviewed": len(received),
            "accepted": len(kept),
            "accepted_correct": sum(r["label"] == "correct" for r in kept),
            "accepted_unsupported": sum(r["label"] == "unsupported" for r in kept),
            "correct_rejected": sum(
                r.get("label") == "correct" and r["decision"] == "rejected"
                for r in arm["rows"]
            ),
        }
        final[mode] = {**arm, "summary": summary}
    require(
        [
            (r["run"], r["parent"], r["parent_request_sha256"])
            for r in final["ranges"]["rows"]
        ]
        == [
            (r["run"], r["parent"], r["parent_request_sha256"])
            for r in final["lines"]["rows"]
        ],
        "Different parent claims",
    )
    if write:
        require(replay, "New receipt requires full replay")
        dump_json(PUBLIC, final)
    else:
        require(final == stored, "Published totals differ")
    return final


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    for name, arm in audit(args.replay, args.write).items():
        print(name, arm["summary"], arm["calls"], arm["elapsed_s"])
