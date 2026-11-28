"""Check addendum scores against the original reports; optionally replay model inputs."""

import argparse
import json
from collections import Counter
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from eval.dotnet_followup import PUBLIC, fingerprint
from eval.followup_report_trial import prepare, sources
from eval.score_public_batch import metrics
from eval.web_report_quality import EVIDENCE, ROOT, current_batch, dotnet_profiles, read
from lab_web.cases import records_for
from stealer_agent.evidence_cards import create_card_report
from stealer_agent.journal import Journal, canonical, dump_json, verify_journal

GRADES = ROOT / "eval/adjudications/dotnet-followup-reports.json"
RECEIPT = EVIDENCE / "web-dotnet-followup-reports.json"


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def stage(sample, mode, labels, donor, sources_by_arm):
    binding = labels["journals"][sample + "/" + mode]
    original = donor["samples"][sample]
    if mode == "mixed":
        path = (
            ROOT
            / "runs"
            / original["run"]
            / "supplements"
            / binding["id"]
            / "events.jsonl"
        )
    else:
        path = (
            ROOT
            / "private/followup-reports"
            / labels["trial"]
            / sample
            / mode
            / "events.jsonl"
        )
    verify_journal(path)
    require(fingerprint(path) == binding["sha256"], "Different measured run")
    events = list(map(json.loads, path.read_bytes().splitlines()))
    start, end = events[0], events[-1]
    require(
        start["event"] == "start" and start["model"] == donor["model_digest"],
        "Different local model",
    )
    if mode == "mixed":
        require(
            start["run"] == original["run"]
            and end["event"] == "supplement_finished"
            and start["parent_sha256"] == original["parent_sha256"]
            and start["sample_sha256"] == original["sample_sha256"]
            and start["output_sha256"] == original["output_sha256"],
            "Unbound web extension",
        )
        searches = [x for x in events if x["event"] == "search"]
        require(
            [x["mode"] for x in searches] == ["fixed", "fixed", "adaptive", "adaptive"],
            "Unexpected hybrid policy",
        )
        queries = [x["observation"] for x in searches]
        require(
            all(
                q["evidence_id"] == start["fresh_eid"]
                and q["output_sha256"] == start["output_sha256"]
                and q["sample_sha256"] == start["sample_sha256"]
                for q in queries
            ),
            "Unexpected VM source",
        )
        (seed,) = [
            r
            for r in records_for(original["run"]).values()
            if r["tool"] == "decompile_dotnet"
        ]
        old = set(seed["line_map"])
        seconds = end["display"]["seconds"]
    else:
        require(
            start["source"] == donor["journal_sha256"]
            and (start["sample"], start["mode"]) == (sample, mode)
            and end["event"] == "finished"
            and start["selector_sha256"]
            == fingerprint(ROOT / "stealer_agent/followup_report.py")
            and start["reporter_sha256"]
            == fingerprint(ROOT / "stealer_agent/evidence_cards.py"),
            "Different report stage",
        )
        queries, old = sources_by_arm[sample, mode]
        seconds = end["seconds"]
    source, cards = prepare(queries, old)
    asks = [
        e
        for e in events
        if e["event"] == "model_request" and e["phase"] != "choose_query"
    ]
    replies = [
        e
        for e in events
        if e["event"] == "model_response" and e["phase"] != "choose_query"
    ]
    require(len(asks) == len(replies), "Missing model response")
    recorded = iter(zip(asks, replies))

    def playback(messages, schema, phase, exposure):
        req, res = next(recorded)
        require(
            req["phase"] == phase == res["phase"]
            and req["step"] == res["step"]
            and req["messages"] == messages
            and req["schema"] == schema
            and req["evidence"] == exposure,
            "Exact report request differs from captured inference",
        )
        return res["response"]

    with TemporaryDirectory() as tmp:
        raw, checked = create_card_report(
            source,
            original["sample_sha256"],
            playback,
            Journal(Path(tmp) / "verify"),
            max_cards=4,
            card_selector=lambda *args, **kwargs: cards,
        )
    require(
        next(recorded, None) is None and checked == end["checked"],
        "Different final decision",
    )
    if mode != "mixed":
        require(raw == end["raw"], "Different proposals")
    kept = {c["id"] for c in checked["claims"]}
    rows = []
    for c in raw["claims"]:
        ranges = []
        for ref in c["evidence"]:
            rec = source[ref["evidence_id"]]
            a, b = ref["line"], ref["end_line"]
            require(
                rec["output_sha256"] == original["output_sha256"]
                and ref["quote"]
                == "\n".join(rec["line_map"][n] for n in range(a, b + 1)),
                "Quote mismatch",
            )
            ranges.append([a, b])
        rows.append(
            {
                "claim": c["id"],
                "kind": c["kind"],
                "sha256": sha256(canonical(c)).hexdigest(),
                "retained": c["id"] in kept,
                "cited": ranges,
            }
        )
    return {
        "journal_sha256": binding["sha256"],
        "model_digest": donor["model_digest"],
        "rows": rows,
        "cards": len(cards),
        "vm_searches": len(queries),
        "report_calls": len(replies),
        "report_tokens": {
            k: sum(e["metrics"][k] for e in replies)
            for k in ("prompt_tokens", "completion_tokens")
        },
        "seconds": seconds,
        "addendum_verdict": checked["verdict"],
    }


def counted(original, annotations, included):
    # Baseline keys are reconstituted from the recorded mapping. Duplicate false
    # claims have the same key even if reported with different wording.
    hits, errors = set(original["matched_reference_ids"]), set()
    for row in annotations:
        if row["retained"]:
            hits.update(row["hits"])
            errors.update(row["errors"])
    errors -= included
    return metrics(
        Counter(
            correct=len(hits),
            missed=original["reference_units"] - len(hits),
            incorrect=original["incorrect"]
            + sum(e.startswith("wrong/") for e in errors),
            unsupported=original["unsupported"]
            + sum(e.startswith("unverified/") for e in errors),
        )
    )


def audit(replay=False, write=False):
    labels, donor = read(GRADES), read(PUBLIC)
    require(
        set(labels["arms"]) == set(labels["journals"]),
        "Missing measured journal binding",
    )
    stored = {} if write else read(RECEIPT)
    arms = sources()[1] if replay else {}
    final = {}
    web = {
        row["run"]: row
        for row in read(EVIDENCE / "web-dotnet-supplement-actions.json")["sessions"]
    }
    modes = {x.split("/")[1] for x in labels["arms"]}
    for sample, (run, profile_path) in dotnet_profiles().items():
        original = donor["samples"][sample]
        require(
            original["run"] == run
            and original["profile_sha256"] == fingerprint(profile_path),
            "Profile mismatch",
        )
        units = {u["id"]: u for u in read(profile_path)["units"]}
        root = EVIDENCE / "web-dotnet-quality" / run
        base = read(root / "atomic-score.json")["after_filter"]
        kept = set(read(root / "judgments.json")["retained_ids"])
        errors = {
            ("wrong/" if a["label"] == "incorrect" else "unverified/") + a["unit_key"]
            for c in read(root / "atomic-mapping.json")["claims"]
            if c["claim_id"] in kept
            for a in c["atoms"]
            if a["label"] != "correct"
        }
        require(
            len(errors) == base["incorrect"] + base["unsupported"]
            and len(units) == base["reference_units"],
            "Baseline has different false or reference units",
        )
        for mode in sorted(modes):
            key = sample + "/" + mode
            if key not in labels["arms"]:
                continue
            arm = stage(sample, mode, labels, donor, arms) if replay else stored[key]
            grades = labels["arms"][key]
            require(
                arm["journal_sha256"] == labels["journals"][key]["sha256"]
                and arm["model_digest"] == donor["model_digest"]
                and len(arm["rows"]) == len(grades),
                "Unbound grade or ungraded proposal",
            )
            rows = []
            for i, (r, (hits, faults, lines, reason)) in enumerate(
                zip(arm["rows"], grades), 1
            ):
                cited = {n for a, b in r["cited"] for n in range(a, b + 1)}
                require(
                    r["claim"] == "C" + str(i)
                    and lines
                    and reason
                    and set(lines) <= cited
                    and all(e.startswith(("wrong/", "unverified/")) for e in faults),
                    "Bad adjudication",
                )
                for uid in hits:
                    u = units[uid]
                    require(
                        u["kind"] == r["kind"]
                        and all(
                            set(range(ref["line"], ref["end_line"] + 1)) <= cited
                            for ref in u["source_references"]
                        ),
                        "Mapped unit lacks its reference rows",
                    )
                rows.append(
                    {
                        **r,
                        "hits": hits,
                        "errors": faults,
                        "audit_lines": lines,
                        "reason": reason,
                    }
                )
            additional = {
                uid for r in rows if r["retained"] for uid in r["hits"]
            } - set(base["matched_reference_ids"])
            final[key] = {
                **arm,
                "rows": rows,
                "added_units": sorted(additional),
                "newly_retrieved_and_reported": sorted(
                    additional & set(original["needed_rows"])
                ),
                "parent_run": run,
                "baseline": metrics(Counter(base)),
                "combined": counted(base, rows, errors),
            }
            if mode == "mixed":
                ui = web[run]
                require(
                    ui["journal_sha256"] == arm["journal_sha256"]
                    and ui["parent_before"] == ui["parent_after"]
                    and ui["supplement"] == labels["journals"][key]["id"]
                    and ui["cards"] == arm["cards"]
                    and ui["raw_claims"] == len(rows)
                    and ui["retained"] == sum(r["retained"] for r in rows)
                    and ui["model_calls"] == arm["report_calls"] + 2
                    and ui["seconds"] == arm["seconds"]
                    and ui["reopened"]
                    and ui["verified_citation_opened"]
                    and not ui["external_requests"]
                    and not ui["page_errors"],
                    "Browser interaction differs",
                )
                if replay:
                    require(
                        fingerprint(ROOT / "runs" / run / "report.private.json")
                        == ui["parent_after"],
                        "Parent report has changed",
                    )
    if write:
        require(replay, "Private replay required to publish")
        dump_json(RECEIPT, final)
    else:
        require(stored == final, "Recomputed grades differ")
    return final


def pooled(arms):
    baseline = current_batch()["after_filter"]["declared_units"]
    result = {"baseline": baseline}
    for mode in ("fixed", "adaptive", "mixed"):
        counts = Counter(
            {k: baseline[k] for k in ("correct", "incorrect", "unsupported", "missed")}
        )
        for sample in dotnet_profiles():
            row = arms[sample + "/" + mode]
            for k in counts:
                counts[k] += row["combined"][k] - row["baseline"][k]
        result[mode] = metrics(counts)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--write", action="store_true")
    options = parser.parse_args()
    result = audit(options.replay, options.write)
    for name, arm in result.items():
        print(name, arm["report_calls"], arm["added_units"], arm["combined"])
    print("Three development samples", pooled(result))
