"""Bind the actual web clicks and reuse grades only for byte-equivalent source-backed claims."""

import argparse
from collections import Counter
from hashlib import sha256
import json

from eval.score_public_batch import metrics
from eval.transfer_report_audit import GRADES, PUBLIC, TRIAL, require
from eval.web_report_exposure import source_id
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, dotnet_profiles, read
from lab_web.cases import records_for, trusted_report
from stealer_agent.journal import canonical, dump_json, verify_journal


def signature(claim, records, profile_eid):
    refs = []
    for ref in claim["evidence"]:
        rec = records[ref["evidence_id"]]
        require(
            ref["evidence_id"] == profile_eid,
            "Claim uses a different parser source from the frozen grade",
        )
        require(
            ref["quote"]
            == "\n".join(
                rec["line_map"][n] for n in range(ref["line"], ref["end_line"] + 1)
            ),
            "Changed quote",
        )
        source = {k: rec[k] for k in ("sample_sha256", "tool")}
        refs.append({**source, **{k: v for k, v in ref.items() if k != "evidence_id"}})
    content = {k: v for k, v in claim.items() if k != "id"}
    return sha256(canonical({**content, "evidence": refs})).hexdigest()


def check(run, interaction):
    view = trusted_report(run)
    folder = ROOT / "runs" / run
    log = folder / "events.jsonl"
    verify_journal(log)
    events = list(map(json.loads, log.read_bytes().splitlines()))
    require(
        events[-1]["event"] == "run_finished"
        and events[-1]["result"] == read(folder / "report.private.json"),
        "Missing terminal record",
    )
    meta = read(EVIDENCE / f"web-{run}.json")
    require(
        sha256(log.read_bytes()).hexdigest() == meta["journal_sha256"]
        and meta["displayed_edges_match_terminal"],
        "Different receipt or graph",
    )
    trial = read(PUBLIC)["trial"]
    (case,) = [c for c in trial["cases"] if c["sample_sha256"] == view["sample_sha256"]]
    donor = case["run"]
    source = ROOT / "runs" / donor
    require(
        meta["model_digest"] == trial["model_digest"]
        and sha256((source / "events.jsonl").read_bytes()).hexdigest()
        == case["parent_sha256"],
        "Model or parent differs",
    )
    base = (
        EVIDENCE
        / (
            "web-python-quality"
            if view["sample"] == "public_python2024.bin"
            else "web-dotnet-quality"
        )
        / donor
    )
    profile_path = next(
        (path for r, path in dotnet_profiles().values() if r == donor), PROFILE
    )
    mapping = read(base / "atomic-mapping.json")
    require(
        mapping["profile_sha256"] == sha256(profile_path.read_bytes()).hexdigest()
        and mapping["raw_report_sha256"]
        == sha256((source / "report.model-raw.json").read_bytes()).hexdigest(),
        "Different source grading",
    )
    source_ev, current_ev = records_for(donor), records_for(run)
    profile = read(profile_path)
    source_events = list(
        map(json.loads, (source / "events.jsonl").read_bytes().splitlines())
    )
    old_eid, new_eid = source_id(profile, source_events), source_id(profile, events)
    atoms = {row["claim_id"]: row["atoms"] for row in mapping["claims"]}
    labels = {}
    for c in read(source / "report.model-raw.json")["claims"]:
        key = signature(c, source_ev, old_eid)
        grade = [(a["unit_key"], a["label"]) for a in atoms[c["id"]]]
        require(
            labels.setdefault(key, grade) == grade,
            "Conflicting grade for identical content",
        )
    measured = ROOT / "private/transfer-reports" / TRIAL / donor / "events.jsonl"
    require(
        sha256(measured.read_bytes()).hexdigest() == case["journal_sha256"],
        "Missing measured trial",
    )
    end = json.loads(measured.read_bytes().splitlines()[-1])
    for c in end["checked"]["claims"]:
        digest = sha256(canonical(c)).hexdigest()
        if digest in GRADES:
            labels[signature(c, source_ev, old_eid)] = [
                (key, "correct") for key in GRADES[digest][0]
            ]
    report = events[-1]["result"]["analysis"]
    require(
        report["report_method"] == "evidence-cards/14"
        and interaction["run"] == run
        and not interaction["page_errors"]
        and not interaction["external_requests"],
        "Different run or UI error",
    )
    tagged = {
        c["id"]: c
        for c in report["claims"]
        if c["id"] in report["transfer_evidence_claim_ids"]
    }
    require(
        list(tagged) == [item["id"] for item in interaction["claims"]] and bool(tagged),
        "Different claims opened in browser",
    )
    for item in interaction["claims"]:
        expected = [
            {
                "first": r["line"],
                "last": r["end_line"],
                "output_sha256": current_ev[r["evidence_id"]]["output_sha256"],
            }
            for r in tagged[item["id"]]["evidence"]
        ]
        require(
            expected == item["sources"], "Browser excerpts differ from retained claim"
        )
    grade_file = ROOT / "eval/adjudications" / f"transfer-live-{run}.json"
    manual = read(grade_file)["claims"] if grade_file.exists() else {}
    used = set()
    declared = {u["id"]: u for u in profile["units"]}
    grades, unmatched = {}, []
    for c in report["claims"]:
        key = signature(c, current_ev, new_eid)
        if c["id"] in manual:
            row = manual[c["id"]]
            cited = {
                n for r in c["evidence"] for n in range(r["line"], r["end_line"] + 1)
            }
            require(
                key == row["signature"]
                and row["reason"]
                and set(row["lines"]) <= cited
                and key not in labels,
                "Conflicting or unbound additional grade",
            )
            for uid, label in row["atoms"]:
                require(
                    label in {"correct", "incorrect", "unsupported"}, "Unknown grade"
                )
                if uid in declared:
                    unit = declared[uid]
                    require(
                        label == "correct"
                        and unit["kind"] == c["kind"]
                        and all(
                            set(range(r["line"], r["end_line"] + 1)) <= cited
                            for r in unit["source_references"]
                        ),
                        "Missing declared source coordinates",
                    )
            labels[key] = row["atoms"]
            used.add(c["id"])
        if key not in labels:
            unmatched.append({"id": c["id"], "signature": key})
            continue
        for uid, label in labels[key]:
            require(grades.setdefault(uid, label) == label, "Conflicting source grade")
    require(used == manual.keys(), "Orphan adjudication")
    units = set(declared)
    correct = sum(grades.get(uid) == "correct" for uid in units)
    counts = Counter(grades.values())
    score = (
        metrics(
            dict(
                correct=correct,
                incorrect=counts["incorrect"],
                unsupported=counts["unsupported"],
                missed=len(units) - correct,
            )
        )
        if not unmatched
        else None
    )
    return {
        "run": run,
        "donor": donor,
        "journal_sha256": meta["journal_sha256"],
        "source_profile_sha256": mapping["profile_sha256"],
        "accepted": len(report["claims"]),
        "unmatched": unmatched,
        "graded_score": score,
        "verdict": report["verdict"],
        "interaction": interaction,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run")
    p.add_argument("--write", action="store_true")
    args = p.parse_args()
    out = EVIDENCE / f"transfer-live-{args.run}.json"
    clicks = (
        read(ROOT / "evidence/local" / f"transfer-web-{args.run}.json")
        if args.write
        else read(out)["interaction"]
    )
    result = check(args.run, clicks)
    if args.write:
        dump_json(out, result)
    else:
        require(read(out) == result, "Published data differs")
    print(result["graded_score"], "unmatched:", len(result["unmatched"]))
