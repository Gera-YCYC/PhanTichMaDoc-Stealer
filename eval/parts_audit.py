"""Compare the original single rewrite with independent part reviews on fixed parents."""

import argparse
from hashlib import sha256
import json

from eval.parts_trial import COHORT, TRIALS, replay, require
from eval.narrow_trial import source
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, read
from eval.web_report_exposure import events as run_events, reconstruct as source_records, required_rows, source_id
from stealer_agent.journal import canonical, dump_json, verify_journal
from stealer_agent.slice_review import slice_discrepancy
from stealer_agent.claim_parts import split_review

PUBLIC = EVIDENCE / "split-review.json"
GRADES = ROOT / "eval/adjudications/parts-review.json"
PY_BASE = "review_62cd4ee21387"


def single_rewrites():
    original = read(EVIDENCE / "web-narrow-review.json")["lines"]
    rows = {(r["run"], r["parent"]): r for r in original["rows"] if r["run"] in COHORT.values()}
    web = read(EVIDENCE / ("web-" + COHORT["python"] + ".json"))
    (review,) = [r for r in web["latest_followup_reviews"] if r["id"] == PY_BASE]
    rows[web["run"], review["parent_claim"]] = {
        "decision": review["decision"], "parent_request_sha256": review["original_request_sha256"],
        "label": "unsupported",
    }
    return rows


def score(receipt):
    grades = read(GRADES)
    require(grades["journal_sha256"] == receipt["journal_sha256"], "Unbound grades")
    baseline = single_rewrites()
    flags = receipt["slice_flags"]
    results = {}
    counts = ("reviewed", "kept", "kept_correct", "kept_incorrect", "kept_unsupported",
              "correct_rejected", "parents_with_correct_kept")
    observed = set()
    parents = set()
    for name in ("single", "parts", "parts_after_slice_check"):
        results[name] = dict.fromkeys(counts, 0)
    for row in receipt["parents"]:
        key = row["run"], row["parent"]
        require(key in baseline and key not in parents, "Changed or duplicated parent")
        parents.add(key)
        prior = baseline[key]
        require(prior["parent_request_sha256"] == row["parent_request_sha256"],
                "Different parent request")
        candidates = [(prior["decision"] == "accepted", prior["label"])]
        split, checked = [], []
        for p in row["parts"]:
            sig = p["fingerprint"]
            require(sig not in observed and sig in grades["grades"], "Ungraded or repeated part")
            observed.add(sig)
            label = grades["grades"][sig]["label"]
            require(label in {"correct", "unsupported", "incorrect"}, "Unknown grade")
            split.append((p["kept"], label))
            checked.append((p["kept"] and sig not in flags, label))
        for name, items in zip(results, (candidates, split, checked), strict=True):
            total = results[name]
            total["reviewed"] += len(items)
            total["parents_with_correct_kept"] += any(ok and label == "correct" for ok, label in items)
            for keep, label in items:
                if keep:
                    total["kept"] += 1
                    total["kept_" + label] += 1
                elif label == "correct":
                    total["correct_rejected"] += 1
    require(parents == set(baseline) and observed == set(grades["grades"])
            and set(flags) <= observed, "Different graded cohort")
    focus = receipt["a09_source"]
    unit = next(u for u in read(PROFILE)["units"] if u["id"] == "PY24-A09")
    required = {n for ref in unit["source_references"] for n in range(ref["line"], ref["end_line"] + 1)}
    row = next(r for r in receipt["parents"] if (r["run"], r["parent"]) == (COHORT["python"], "C7"))
    used = {n for p in row["parts"] for a, b in p["ranges"] for n in range(a, b + 1)}
    require(focus == {"unit": unit["id"], "run": row["run"], "parent": row["parent"],
                      "reference_rows_in_prompt": sorted(required), "reference_rows_selected": sorted(used & required)},
            "Displayed A09 coordinates differ from the profile or selected references")
    return results


def reconstruct(trial):
    path = TRIALS / trial / "events.jsonl"
    receipt = replay(path)
    events = list(map(json.loads, path.read_bytes().splitlines()))
    flags = {}
    for event in events:
        if event["event"] != "parts":
            continue
        tool = "decode_python_literals" if event["run"] == COHORT["python"] else "decompile_dotnet"
        for item in event["results"]:
            claim = item["claim"]
            found = slice_discrepancy(claim, tool)
            if found:
                flags[sha256(canonical(claim)).hexdigest()] = found
    receipt["slice_flags"] = flags
    base = read(EVIDENCE / "web-narrow-review.json")["lines"]
    log = ROOT / "private/narrow-trials" / base["trial"] / "events.jsonl"
    verify_journal(log)
    require(sha256(log.read_bytes()).hexdigest() == base["journal_sha256"]
            and receipt["model_digest"] == base["model_digest"], "Different baseline")
    run = None
    metrics = []
    for event in map(json.loads, log.read_bytes().splitlines()):
        if event["event"] == "source_bound":
            run = event["run"]
        elif event["event"] == "model_response" and run in (COHORT["gomorrah"], COHORT["mercurial"]):
            metrics.append(event["metrics"])
    p = ROOT / "runs" / COHORT["python"] / "claim-reviews" / PY_BASE / "events.jsonl"
    verify_journal(p)
    web = read(EVIDENCE / ("web-" + COHORT["python"] + ".json"))
    (prior,) = [r for r in web["latest_followup_reviews"] if r["id"] == PY_BASE]
    require(sha256(p.read_bytes()).hexdigest() == prior["journal_sha256"]
            and receipt["model_digest"] == web["model_digest"], "Different Python follow-up")
    metrics.extend(e["metrics"] for e in map(json.loads, p.read_bytes().splitlines())
                   if e["event"] == "model_response")
    receipt["single_cost"] = {"calls": len(metrics), "input_tokens": sum(m["prompt_tokens"] for m in metrics),
                              "output_tokens": sum(m["completion_tokens"] for m in metrics),
                              "inference_s": round(sum(m["latency_s"] for m in metrics), 3)}
    profile = read(PROFILE)
    unit = next(u for u in profile["units"] if u["id"] == "PY24-A09")
    originals = {}
    for run in ("20261127T211223_9602dfdd", "20261127T230331_8bd30a1f"):
        originals.update(source_records(run_events(run)))
    primary = COHORT["python"]
    original = run_events(primary)
    record = source_records(original)[source_id(profile, original)]
    needed = required_rows(unit, record, profile, originals)
    _, _, cases = source("python", primary)
    parent, _, request = next(t for t in cases if t[0]["id"] == "C7")
    numbered_code = json.loads(request["messages"][-1]["content"])["code"].splitlines()
    require(all(f"{n} | {record['line_map'][n]}" in numbered_code for n in needed),
            "Expected A09 lines not all present in the parent request")
    row = next(r for r in receipt["parents"] if (r["run"], r["parent"]) == (primary, parent["id"]))
    chosen = {n for part in row["parts"] for a, b in part["ranges"] for n in range(a, b + 1)}
    receipt["a09_source"] = {"unit": unit["id"], "run": primary, "parent": parent["id"],
                             "reference_rows_in_prompt": sorted(needed),
                             "reference_rows_selected": sorted(needed & chosen)}
    receipt["scores"] = score(receipt)
    return receipt


def web_details(data):
    grades = read(GRADES)["grades"]
    names = {run: sample for sample, run in COHORT.items()}
    return [{"sample": names[r["run"]], "run": r["run"], "parent": r["parent"],
             "number": index, "kept": part["kept"], "ranges": part["ranges"],
             "flagged": part["fingerprint"] in data["slice_flags"], **grades[part["fingerprint"]]}
            for r in data["parents"] for index, part in enumerate(r["parts"], 1)]


def check_click(review_id, receipt):
    ui = read(ROOT / "evidence/local" / f"parts-web-{review_id}.json")
    run, cid = ui["run"], ui["parent"]
    folder = ROOT / "runs" / run
    child = folder / "parts-reviews" / review_id / "events.jsonl"
    verify_journal(child)
    log = iter(map(json.loads, child.read_bytes().splitlines()))
    first = next(log)
    sample = next(k for k, v in COHORT.items() if v == run)
    parent_hash, model, parents = source(sample, run)
    parent, _, request = next(case for case in parents if case[0]["id"] == cid)
    require(first["event"] == "review_started" and first["mode"] == "parts"
            and first["source_journal_sha256"] == parent_hash and first["parent"] == cid
            and first["model_digest"] == ui["model_digest"] == receipt["model_digest"] == model
            and first["original_request_sha256"] == request["messages_sha256"]
            and ui["vm_ready"] and not ui["errors"] and not ui["external"],
            "Unbound browser run")
    steps = 0

    def recorded(messages, schema, phase, evidence):
        nonlocal steps
        steps += 1
        req, reply = next(log), next(log)
        require(req["event"] == "model_request" and reply["event"] == "model_response"
                and steps == req["step"] == reply["step"] and phase == req["phase"] == reply["phase"]
                and messages == req["messages"] and schema == req["schema"] and evidence == req["evidence"],
                "Different child review messages")
        return reply["response"]

    tool = request["evidence"][0]["tool"]
    outcomes = split_review(parent, tool, recorded)
    last = next(log)
    require(last["event"] == "review_finished" and last["outcomes"] == outcomes
            and next(log, None) is None and steps == ui["model_calls"], "Different child review")
    display = last["display"]
    expected = []
    signatures = []
    for i, (part, entry) in enumerate(zip(outcomes, display["parts"], strict=True), 1):
        claim = part["claim"]
        require(entry["kept"] == part["check"]["supported"]
                and entry["slice_check"] == slice_discrepancy(claim, tool), "Incorrect display state")
        signatures.append(sha256(canonical(claim)).hexdigest())
        for r in claim["evidence"]:
            numbers = list(range(r["line"], r["end_line"] + 1))
            window = display["windows"][f"{r['evidence_id']}:{numbers[0]}:{numbers[-1]}"]
            expected.append({"part": i, "lines": numbers, "source_sha256": window["output_sha256"]})
    require(ui["opened"] == expected, "Browser did not open all references")
    trial_row = next(r for r in receipt["parents"] if (r["run"], r["parent"]) == (run, cid))
    return {**ui, "journal_sha256": sha256(child.read_bytes()).hexdigest(),
            "parent_journal_sha256": parent_hash, "parent_report_sha256": sha256((folder / "report.private.json").read_bytes()).hexdigest(),
            "matches_trial": signatures == [p["fingerprint"] for p in trial_row["parts"]]
                             and [p["check"]["supported"] for p in outcomes] == [p["kept"] for p in trial_row["parts"]]}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--write", metavar="TRIAL")
    cli.add_argument("--replay", action="store_true")
    cli.add_argument("--clicks", nargs="+", metavar="REVIEW")
    args = cli.parse_args()
    if args.write:
        fresh = reconstruct(args.write)
        fresh["web"] = [check_click(review_id, fresh) for review_id in args.clicks or []]
        dump_json(PUBLIC, fresh)
    data = read(PUBLIC)
    require(score(data) == data["scores"], "Published score differs")
    if args.replay:
        rebuilt = reconstruct(data["trial"])
        rebuilt["web"] = [check_click(w["review"], rebuilt) for w in data["web"]]
        require(rebuilt == data, "Private replay differs")
    print(json.dumps(data["scores"]))
