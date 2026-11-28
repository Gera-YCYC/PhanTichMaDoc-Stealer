"""Audit the six extra evidence cards. Public mode needs only the Git checkout."""

import argparse
import json
from collections import Counter
from hashlib import sha256

from eval.card_coverage import refs
from eval.web_report_exposure import events, source_id
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, dotnet_profiles, read
from scripts.replay_card_report import reconstruct
from stealer_agent.journal import canonical, dump_json, verify_journal

LABELS = ROOT / "eval/adjudications/web-card-supplements.json"
RECEIPT = EVIDENCE / "web-card-supplements.json"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def log_cards(log, expected):
    cards = next(e["cards"] for e in log if e["event"] == "evidence_cards_selected")
    requests = [
        json.loads(e["messages"][-1]["content"])
        for e in log
        if e["event"] == "model_request" and e["phase"] == "card_generate"
    ]
    by_id = {c["card_id"]: c for c in cards}
    ranges = []
    for request in requests:
        sections, coords = [], []
        for index, ref in enumerate(refs(by_id[request["card_id"]]), 1):
            start, end = ref["line"], ref["end_line"]
            lines = ref["quote"].split("\n")
            demand(len(lines) == end - start + 1, "Incomplete numbered section")
            numbered = "\n".join(f"{n} | {s}" for n, s in enumerate(lines, start))
            sections.append(f"SECTION {index} original lines {start}-{end}\n{numbered}")
            coords.append([ref["evidence_id"], start, end])
        demand(
            request["code"] == "\n\n".join(sections),
            "Actual prompt differs from selected text",
        )
        ranges.append(coords)
    demand(ranges == expected, "Unexpected section ranges or generation count")


def reproduce(sample, lab, coverage):
    run = lab["source"]
    receipt = read(EVIDENCE / f"web-{run}.json")
    folder = ROOT / "private/report-experiments" / lab["experiment"]
    path = folder / "events.jsonl"
    verify_journal(path)
    stage = [json.loads(s) for s in path.read_bytes().splitlines()]
    original = events(run)
    source_hash = digest(ROOT / "runs" / run / "events.jsonl")
    start, end = stage[0], stage[-1]
    demand(
        start["event"] == "replay_started"
        and end["event"] == "replay_finished"
        and digest(path) == lab["journal_sha256"]
        and source_hash
        == start["source_journal_sha256"]
        == receipt["journal_sha256"]
        == coverage["journal_sha256"]
        and start["source_run"] == run
        and start["model"]["digest"] == receipt["model_digest"],
        "Unbound stage or source run",
    )
    settings = next(e for e in stage if e["event"] == "replay_settings")
    demand(
        settings["method"] == "supplement"
        and settings["max_cards"] == 2
        and settings["api_guidance"],
        "Unexpected treatment",
    )
    base_ranges = coverage["baseline"]["card_ranges"]
    extra_ranges = coverage["two_extra"]["card_ranges"]
    demand(extra_ranges[:-2] == base_ranges, "Original windows changed")
    log_cards(original, base_ranges)
    log_cards(stage, extra_ranges[-2:])
    profile_path = PROFILE if sample == "python" else dotnet_profiles()[sample][1]
    profile = read(profile_path)
    demand(
        profile["sample_sha256"] == receipt["sha256"]
        and digest(profile_path) == coverage["profile_sha256"],
        "Different sample or profile",
    )
    eid = source_id(profile, original)
    evidence = reconstruct(original)[eid]["line_map"]
    units = {u["id"]: u for u in profile["units"]}
    raw_file, final_file = (
        folder / "report.model-raw.json",
        folder / "report.checked.json",
    )
    raw, checked = read(raw_file)["claims"], read(final_file)
    demand(
        raw == [e["claim"] for e in stage if e["event"] == "card_claim_proposed"],
        "Raw proposals differ",
    )
    retained = {c["id"] for c in checked["claims"]}
    rejected = {r["claim"]["id"] for r in checked["rejected_claims"]}
    decisions = {
        e["claim_id"]: e["check"]["supported"]
        for e in stage
        if e["event"] == "card_claim_review"
    }
    demand(
        set(decisions)
        == set(lab["claims"])
        == {c["id"] for c in raw}
        == retained | rejected
        and not retained & rejected
        and {i for i, ok in decisions.items() if ok} == retained
        and len(retained) == end["accepted_claims"]
        and len(rejected) == end["rejected_claims"],
        "Wrong partition",
    )
    rows = []
    for c in raw:
        cid = c["id"]
        label, statement, reason, mapped = lab["claims"][cid]
        lines, coordinates = set(), []
        for ref in c["evidence"]:
            a, b = ref["line"], ref["end_line"]
            demand(
                ref["evidence_id"] == eid
                and ref["quote"] == "\n".join(evidence[n] for n in range(a, b + 1)),
                "Claim cites different source",
            )
            lines.update(range(a, b + 1))
            coordinates.append([a, b])
        for key in mapped:
            unit = units[key]
            demand(
                unit["kind"] == c["kind"]
                and all(
                    set(range(r["line"], r["end_line"] + 1)) <= lines
                    for r in unit["source_references"]
                ),
                "Mapped proposition lacks its declared source rows",
            )
        demand(label in ("correct", "unsupported", "incorrect"), "Unknown audit label")
        rows.append(
            {
                "claim": cid,
                "kind": c["kind"],
                "label": label,
                "summary": statement,
                "reason": reason,
                "supported_units": mapped,
                "retained": cid in retained,
                "lines": coordinates,
                "claim_sha256": sha256(canonical(c)).hexdigest(),
            }
        )
    replies = [e for e in stage if e["event"] == "model_response"]
    phases = dict(Counter(e["phase"] for e in replies))
    metrics = end["metrics"]
    demand(
        len(replies) == metrics["model_calls"]
        and all(
            metrics[k] == sum(e["metrics"][k] for e in replies)
            for k in ("prompt_tokens", "completion_tokens")
        ),
        "Different inference accounting",
    )
    return {
        "source": run,
        "experiment": lab["experiment"],
        "journal_sha256": digest(path),
        "source_journal_sha256": source_hash,
        "raw_sha256": digest(raw_file),
        "checked_sha256": digest(final_file),
        "model_digest": start["model"]["digest"],
        "selector_sha256": start["source_files"]["eval/card_coverage.py"],
        "config_sha256": start["config_file_sha256"],
        "metrics": metrics,
        "phases": phases,
        "rows": rows,
    }


def audit(*, replay=False, write=False):
    labels = read(LABELS)
    coverage = {
        r["run"]: r for r in read(EVIDENCE / "web-card-coverage.json")["results"]
    }
    archive = {} if write else read(RECEIPT)
    out = {}
    for sample, lab in labels.items():
        c = coverage[lab["source"]]
        row = reproduce(sample, lab, c) if replay else archive[sample]
        donor = "web-python-quality" if sample == "python" else "web-dotnet-quality"
        original = read(EVIDENCE / donor / lab["source"] / "atomic-score.json")
        ids = original["after_filter"]["matched_reference_ids"]
        included = {
            uid
            for r in row["rows"]
            if r["retained"] and r["label"] == "correct"
            for uid in r["supported_units"]
        }
        demand(
            row["source"] == lab["source"]
            and row["experiment"] == lab["experiment"]
            and row["journal_sha256"] == lab["journal_sha256"]
            and row["source_journal_sha256"] == c["journal_sha256"]
            and [r["claim"] for r in row["rows"]] == list(lab["claims"])
            and all(
                [r["label"], r["summary"], r["reason"], r["supported_units"]]
                == lab["claims"][r["claim"]]
                for r in row["rows"]
            ),
            "Grading differs from published decisions",
        )
        out[sample] = {
            **row,
            "new_accepted_units": sorted(included - set(ids)),
            "reference_units": c["units"],
            "visible_before": len(c["baseline"]["in_one_card"]),
            "visible_after": len(c["two_extra"]["in_one_card"]),
        }
    if write:
        demand(replay, "Private artifacts required for new receipt")
        dump_json(RECEIPT, out)
    else:
        demand(out == archive, "Public and reproduced receipts differ")
    return out


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--replay", action="store_true")
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    for name, record in audit(replay=args.replay, write=args.write).items():
        print(name, record["phases"], record["new_accepted_units"])
