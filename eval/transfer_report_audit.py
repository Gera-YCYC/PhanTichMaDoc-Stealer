"""Grade source-bound transfer statements against the pre-existing development profiles."""

import argparse
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from eval.score_public_batch import metrics
from eval.web_report_quality import (
    EVIDENCE,
    PROFILE,
    ROOT,
    current_batch,
    dotnet_profiles,
    read,
)
from stealer_agent.journal import canonical, dump_json, verify_journal

TRIAL = "trial_301512163b45"
PUBLIC = EVIDENCE / "transfer-report-comparison.json"
# Labels bind the full claim including source quotes. A true observation outside
# the predeclared coordinates earns sentence credit only.
GRADES = {
    "8dc62a0fe0bb2948b5981dcee1e2aee8ef41297974b8bca3e1b72a4e133d42da": (
        ["PY24-A19"],
        "At 96–98 bytes from the attachment parameter supply the MIME payload.",
    ),
    "73dd73ff25a6d8ca3ea72815f580b0dad03c3628dcb884ce79aead93a7f92b60": (
        [],
        "Serialization and the send argument refer to the same value. The statement does not establish which collected data the file contained.",
    ),
    "6b4704921f2969cf3bf70187179a4dd1d20670be6047b40f93aeb660d2746864": (
        [],
        "Real upload site at 3599–3603. The logs-fragment unit requires the separately declared occurrence at 3573 and 3577.",
    ),
    "da04267d0480b2cdd1235fd64fca086624e2711ab989edba402af2d19225988d": (
        ["screen-fragment"],
        "The relative prefix at 3677 is used in the address expression at 3681. The host is unresolved.",
    ),
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def replay(case, trial):
    from lab_web.cases import records_for, trusted_report
    from stealer_agent.evidence_cards import finalize_claims
    from stealer_agent.flow_review import review
    from stealer_agent.journal import Journal

    run = case["run"]
    base = ROOT / "runs" / run
    path = ROOT / "private/transfer-reports" / TRIAL / run / "events.jsonl"
    for file, digest in [
        (path, case["journal_sha256"]),
        (base / "events.jsonl", case["parent_sha256"]),
    ]:
        verify_journal(file)
        require(sha256(file.read_bytes()).hexdigest() == digest, "Journal hash differs")
    events = list(map(json.loads, path.read_bytes().splitlines()))
    first, last = events[0], events[-1]
    sample = case["sample_sha256"]
    require(
        first["event"] == "start"
        and last["event"] == "finished"
        and first["run"] == run
        and first["sample_sha256"] == sample
        and first["model_digest"]
        == trial["model_digest"]
        == trusted_report(run)["model"]["digest"]
        and first["parent_sha256"] == case["parent_sha256"]
        and first["method_sha256"] == trial["method_sha256"]
        and first["config_sha256"] == trial["config_sha256"],
        "Trial is not bound to the original case",
    )
    records = records_for(run)
    asks = [e for e in events if e["event"] == "model_request"]
    replies = [e for e in events if e["event"] == "model_response"]
    require(len(asks) == len(replies) == len(case["calls"]), "Missing inference")
    pairs = iter(zip(asks, replies, case["calls"]))

    def playback(messages, schema, phase, exposure):
        req, res, usage = next(pairs)
        require(
            req["phase"] == res["phase"] == usage["phase"] == phase
            and req["messages"] == messages
            and req["schema"] == schema
            and req["evidence"] == exposure
            and all(res["metrics"][k] == v for k, v in usage.items() if k != "phase"),
            "Different Qwen input or usage",
        )
        return res["action"]

    original = read(base / "report.private.json")["analysis"]
    raw = read(base / "report.model-raw.json")["claims"]
    claims = deepcopy(raw)
    accepted, rejected = (
        deepcopy(original["claims"]),
        deepcopy(original["rejected_claims"]),
    )
    with TemporaryDirectory() as tmp:
        log = Journal(Path(tmp) / "replay")
        review(records, sample, playback, log, claims, accepted, rejected)
        _, checked = finalize_claims(
            records, sample, claims, accepted, rejected, playback, log
        )
    require(
        next(pairs, None) is None and checked == last["checked"],
        "Different final report",
    )
    require(
        checked["verdict"] == case["verdict"]
        and checked["claims"][: len(original["claims"])] == original["claims"],
        "Previous accepted claims differ",
    )
    require(
        len(checked["claims"]) == case["retained"]
        and len(original["claims"]) == case["baseline_claims"],
        "Wrong report counts",
    )
    routes = {
        e["claim_id"]: e["route"]
        for e in events
        if e["event"] == "flow_review_decision"
    }
    for c, row in zip(claims[len(raw) :], case["rows"], strict=True):
        require(
            c["id"] == row["id"]
            and routes[c["id"]] == row["route"]
            and sha256(canonical(c)).hexdigest() == row["sha256"]
            and c["kind"] == row["kind"]
            and (c in checked["claims"]) == row["retained"],
            "Different statement or review",
        )
        require(
            [[r["line"], r["end_line"]] for r in c["evidence"]] == row["ranges"],
            "Different coordinates",
        )
        for ref in c["evidence"]:
            rec = records[ref["evidence_id"]]
            require(
                rec["sample_sha256"] == sample
                and ref["quote"]
                == "\n".join(
                    rec["line_map"][n] for n in range(ref["line"], ref["end_line"] + 1)
                ),
                "Quote mismatch",
            )


def audit(trial, private=False):
    baseline = current_batch()["after_filter"]
    batch = read(EVIDENCE / "web-current-batch.json")["runs"]
    require(trial["trial"] == TRIAL, "Different experiment")
    profiles = {run: path for run, path in dotnet_profiles().values()}
    seen, accepted, summary = set(), 0, []
    added = {"declared_units": 0, "ioc_and_attack": 0}
    verdicts = 0
    for case, donor in zip(trial["cases"], batch, strict=True):
        run = case["run"]
        require(
            case["parent_sha256"] == donor["journal"]["sha256"]
            and run == donor["run_id"]
            and case["sample_sha256"] == donor["sample_sha256"]
            and case["sample"] == donor["sample"]
            and trial["model_digest"] == donor["model"]["digest"],
            "Different comparison cohort",
        )
        profile = read(profiles.get(run, PROFILE))
        units = {u["id"]: u for u in profile["units"]}
        folder = "web-dotnet-quality" if run in profiles else "web-python-quality"
        original = read(EVIDENCE / folder / run / "atomic-score.json")["after_filter"]
        require(
            profile["sample_sha256"] == donor["sample_sha256"]
            and case["baseline_claims"] == donor["accepted_claims"],
            "Different baseline",
        )
        if private:
            replay(case, trial)
        verdicts += (
            case["verdict"] == "malicious"
        )  # All three development samples are labeled malicious.
        hits = set()
        for row in case["rows"]:
            digest = row["sha256"]
            require(digest not in seen, "Duplicate adjudication")
            seen.add(digest)
            mapped, _ = GRADES[digest]
            lines = {n for a, b in row["ranges"] for n in range(a, b + 1)}
            for uid in mapped:
                u = units[uid]
                require(
                    row["kind"] == u["kind"]
                    and all(
                        set(range(ref["line"], ref["end_line"] + 1)) <= lines
                        for ref in u["source_references"]
                    ),
                    "Insufficient reference coverage",
                )
            if row["retained"]:
                accepted += 1
                hits.update(mapped)
        require(
            case["baseline_claims"] + sum(r["retained"] for r in case["rows"])
            == case["retained"],
            "New claim count differs",
        )
        new = hits - set(original["matched_reference_ids"])
        summary.append({"sample": case["sample"], "new_units": sorted(new)})
        added["declared_units"] += len(new)
        added["ioc_and_attack"] += sum(
            units[u]["kind"] in {"ioc", "attack"} for u in new
        )
    require(seen == GRADES.keys(), "Incomplete cohort")
    scores = {}
    for key, n in added.items():
        b = baseline[key]
        scores[key] = metrics(
            {**b, "correct": b["correct"] + n, "missed": b["missed"] - n}
        )
    b = baseline["sentences"]
    count = b["count"] + accepted
    scores["sentences"] = {
        "count": count,
        "correct": b["correct"] + accepted,
        "incorrect": b["incorrect"],
        "unsupported": b["unsupported"],
        "citations": b["citations"] + accepted,
        "citation_rate": (b["citations"] + accepted) / count,
        "source_supported_rate": (b["correct"] + accepted) / count,
        "hallucination_rate": b["unsupported"] / count,
    }
    return {
        "baseline": baseline,
        "reviewed": scores,
        "samples": summary,
        "strict_correct_verdicts": verdicts,
        "sample_count": len(summary),
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--replay", action="store_true")
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    if args.write and not args.replay:
        p.error("--write requires --replay")
    trial = (
        read(ROOT / "private/transfer-reports" / TRIAL / "receipt.json")
        if args.replay
        else read(PUBLIC)["trial"]
    )
    result = {
        "trial": trial,
        "grades": {k: list(v) for k, v in GRADES.items()},
        "scores": audit(trial, args.replay),
    }
    if args.write:
        dump_json(PUBLIC, result)
    else:
        require(read(PUBLIC) == result, "Published scores differ")
    print(json.dumps(result["scores"]["reviewed"], indent=2))
