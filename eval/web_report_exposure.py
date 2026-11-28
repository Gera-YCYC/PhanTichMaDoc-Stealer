"""Locate missing reference rows in the actual report-generation requests."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, read
from scripts.replay_card_report import reconstruct
from stealer_agent.journal import canonical, dump_json, verify_journal


def events(run):
    path = ROOT / "runs" / run / "events.jsonl"
    verify_journal(path)
    return [json.loads(s) for s in path.read_bytes().splitlines()]


def request_windows(journal, eid, lines):
    """Count only rows verifiably present in actual candidate-authoring messages."""
    windows = []
    for event in journal:
        phase = event.get("phase")
        if event["event"] != "model_request" or phase not in {
            "card_generate",
            "operation_review",
            "technique_review",
        }:
            continue
        if sha256(canonical(event["messages"])).hexdigest() != event["messages_sha256"]:
            raise ValueError("Changed model request")
        payload = json.loads(event["messages"][-1]["content"])
        present = set()
        if phase == "card_generate":
            code = set(payload["code"].splitlines())
            for group in event["evidence"]:
                if group["evidence_id"] != eid:
                    continue
                for row in group["lines"]:
                    n, text = row["line"], row["text"]
                    if lines[n] != text or f"{n} | {text}" not in code:
                        raise ValueError("Card row differs from projected source")
                    present.add(n)
        else:
            for item in payload.values():
                for ref in item["references"]:
                    if ref["evidence_id"] == eid:
                        interval = range(
                            ref["line"], ref.get("end_line", ref["line"]) + 1
                        )
                        if "\n".join(lines[n] for n in interval) != ref["quote"]:
                            raise ValueError(
                                "Typed evidence differs from projected source"
                            )
                        present.update(interval)
        windows.append(present)
    return windows


def locate(run, profile_path, reviews, historical=None):
    profile = read(profile_path)
    journal = events(run)
    receipt = read(EVIDENCE / f"web-{run}.json")
    log = ROOT / "runs" / run / "events.jsonl"
    if sha256(log.read_bytes()).hexdigest() != receipt["journal_sha256"]:
        raise ValueError("Different journal")
    normalized = {
        r["parser_source_sha256"]
        for r in profile["source_references"]
        if isinstance(r, dict) and "parser_source_sha256" in r
    }
    observations = [e["model_visible"] for e in journal if e["event"] == "observation"]
    outputs = {
        r["output_sha256"]
        for r in profile["source_references"]
        if isinstance(r, dict) and "output_sha256" in r
    }
    ids = {
        r["evidence_id"]
        for r in observations
        if r["sample_sha256"] == profile["sample_sha256"]
        and (
            (
                r["tool"] == "decode_python_literals"
                and r.get("syntax_context", {}).get("source_sha256") in normalized
            )
            or (r["tool"] == "decompile_dotnet" and r["output_sha256"] in outputs)
        )
    }
    if len(ids) != 1:
        raise ValueError("Expected one matching source from the reference profile")
    eid = ids.pop()
    source = reconstruct(journal)[eid]
    lines = source["line_map"]
    windows = request_windows(journal, eid, lines)
    visible = set().union(*windows)
    score = read(EVIDENCE / reviews / run / "atomic-score.json")
    if score["profile_sha256"] != sha256(profile_path.read_bytes()).hexdigest():
        raise ValueError("Changed reference profile")
    rows = []
    for unit in profile["units"]:
        uid = unit["id"]
        required = set()
        for ref in unit["source_references"]:
            interval = range(ref["line"], ref["end_line"] + 1)
            if historical is not None:
                origin = historical[ref["evidence_id"]]
                if origin["sample_sha256"] != profile["sample_sha256"]:
                    raise ValueError("Reference from a different sample")
                for n in interval:
                    original = origin["line_map"][n]
                    if n in lines and (
                        lines[n] != original
                        or origin["line_metadata"][n] != source["line_metadata"][n]
                    ):
                        raise ValueError("Different source coordinates")
            elif not any(
                isinstance(r, dict)
                and r.get("evidence_id") == ref["evidence_id"]
                and r.get("output_sha256") == source["output_sha256"]
                for r in profile["source_references"]
            ):
                raise ValueError("Reference rows belong to another ILSpy output")
            required.update(interval)
        if uid in score["after_filter"]["matched_reference_ids"]:
            reason = "retained"
        elif uid in score["raw"]["matched_reference_ids"]:
            reason = "lost_at_review"
        elif required - lines.keys():
            reason = "missing_from_retrieval"
        elif any(required <= window for window in windows):
            reason = "in_one_request"
        elif required <= visible:
            reason = "split_across_requests"
        else:
            reason = "retrieved_but_not_in_requests"
        rows.append({"unit": uid, "category": reason})
    return {
        "run": run,
        "journal_sha256": receipt["journal_sha256"],
        "profile_sha256": score["profile_sha256"],
        "source_sha256": next(iter(normalized))
        if normalized
        else source["output_sha256"],
        "report_requests": len(windows),
        "counts": dict(Counter(r["category"] for r in rows)),
        "units": rows,
    }


def evaluate(branch="python"):
    if branch != "python":
        from eval.web_report_quality import dotnet_profiles

        run, profile_path = dotnet_profiles()[branch]
        return {
            "runs": [locate(run, profile_path, "web-dotnet-quality")],
            "scope": "Rows in the pinned ILSpy output and logged report requests. Presence does not establish a complete data flow or human validation.",
        }
    historical = {}
    for run in ("20261127T211223_9602dfdd", "20261127T230331_8bd30a1f"):
        historical.update(reconstruct(events(run)))
    return {
        "runs": [
            locate(run, PROFILE, "web-python-quality", historical)
            for run in read(EVIDENCE / "web-stability-python.json")["runs"]
        ],
        "scope": "Declared reference rows in tool results and three candidate-generation phases. Row presence does not prove sufficient context, model attention or causality.",
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sample", default="python")
    args = parser.parse_args()
    result = evaluate(args.sample)
    if args.output:
        dump_json(args.output, result)
    else:
        if result != read(EVIDENCE / f"web-{args.sample}-exposure.json"):
            raise ValueError("Published exposure differs from the original requests")
    for row in result["runs"]:
        print(row["run"], row["counts"])
