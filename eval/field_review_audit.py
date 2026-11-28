"""Score exact cited lines on two distinct development methods; optional local log replay."""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from stealer_agent.journal import verify_journal

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "deliverables/real-demo-evidence/web-field-reviews.json"
# Independent source reading. Two callers reach the same second method.
# 1900 writes via the request stream opened at 1897. 1906 requests the response.
REFERENCE = {
    (1913, 1934): {"file_read": {1921}, "http_io": set()},
    (1888, 1911): {"file_read": set(), "http_io": {1900, 1906}},
}


def score(receipts, phase):
    counts = dict(
        supported_positive=0, wrong_positive=0, insufficient=0, correct_abstention=0
    )
    seen = {}
    for receipt in receipts:
        for case in receipt["cases"]:
            if case["status"] != "source_candidate":
                continue
            key = tuple(case["ranges"]["method"])
            if (
                case["sample_sha256"]
                != "926755cc31c239edc78b3ef4aa3b3cc64fbe7209d907f9d1cdaa4b560662adfc"
            ):
                raise ValueError("Unexpected source for development labels")
            answers = case["answers"][phase]
            if key in seen:
                if answers != seen[key]:
                    raise ValueError("Repeated callers disagree; grade the discrepancy separately")
                continue
            seen[key] = answers
            for question, witnesses in REFERENCE[key].items():
                n = case["answers"][phase][question]
                if n in witnesses:
                    grade = "supported_positive"
                elif n:
                    grade = "wrong_positive"
                else:
                    grade = "insufficient" if witnesses else "correct_abstention"
                counts[grade] += 1
    if set(seen) != set(REFERENCE):
        raise ValueError("Missing measured method")
    return counts


def replay(receipts):
    for receipt in receipts:
        for c in receipt["cases"]:
            base = ROOT / "runs" / c["run"]
            parent = base / "supplements" / c["supplement"] / "events.jsonl"
            path = parent.parent / "field-reviews" / c["id"] / "events.jsonl"
            for journal in [parent, path]:
                verify_journal(journal)
            for file, digest in [
                (parent, c["parent_sha256"]),
                (path, c["journal_sha256"]),
                (base / "report.private.json", receipt["report_sha256"]),
            ]:
                if sha256(file.read_bytes()).hexdigest() != digest:
                    raise ValueError("Changed private artifact")
            events = [json.loads(s) for s in path.read_bytes().splitlines()]
            start, end = events[0], events[-1]
            if (
                start["model"] != c["model_digest"]
                or start["output_sha256"] != c["output_sha256"]
                or end["event"] != "finished"
            ):
                raise ValueError("Model/source/outcome mismatch")
            for k in [
                "answers",
                "attempts",
                "status",
                "ranges",
                "line",
                "id",
                "seconds",
                "vm_calls",
                "model_calls",
            ]:
                if end["display"][k] != c[k]:
                    raise ValueError("Different displayed result: " + k)
            calls = [e for e in events if e["event"] == "model_response"]
            if len(calls) != c["model_calls"]:
                raise ValueError("Different number of observed model calls")
            for event in calls:
                if event["phase"] in ("call", "with_method"):
                    if event["response"] != c["answers"][event["phase"]]:
                        raise ValueError("Source answers differ from actual model response")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Verify original private journals in the lab",
    )
    args = parser.parse_args()
    data = json.loads(PUBLIC.read_bytes())
    for policy, receipts in data["trials"].items():
        for phase in ("call", "with_method"):
            print(policy, phase, score(receipts, phase))
        if args.replay:
            replay(receipts)


if __name__ == "__main__":
    main()
