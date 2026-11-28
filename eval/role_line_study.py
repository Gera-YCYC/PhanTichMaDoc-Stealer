"""Compare the proposed verdict roles with a second reading of the cited VM lines."""
import argparse
from hashlib import sha256
import json

from eval.ordinal_review_study import journal
from eval.transfer_report_audit import require
from eval.verdict_trial import CONFIG, CONTROLS, EVIDENCE, ROOT, digest, read
from lab_web.cases import RUN, case, records_for
from stealer_agent.journal import Journal, dump_json, record_model_request
from stealer_agent.role_evidence import review_pair, screen
from stealer_agent.role_evidence import FIELDS
from stealer_agent.verdict_support import SUPPORT_KEYS
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient

PLAN = ROOT / "eval/adjudications/role-lines-protocol.json"
LOCAL = ROOT / "private/role-lines/first"
PUBLIC = EVIDENCE / "role-line-study.json"
LIVE_RECEIPT = EVIDENCE / "role-lines-live.json"
NAVIGATION = EVIDENCE / "role-unused-sends-browser.json"
WITNESS_AUDIT = ROOT / "eval/adjudications/role-lines-witness-audit.json"


def file_hash(path):
    return sha256(path.read_bytes()).hexdigest()


def controls(plan):
    require(file_hash(CONTROLS) == plan["existing_controls"], "Control definitions changed")
    return [*read(CONTROLS)["cases"], plan["extra"]]


def pairs(plan):
    for group in controls(plan):
        run = group["run"]
        parent = ROOT / "runs" / run
        log = parent / "events.jsonl"
        report = read(parent / "report.private.json")
        records = records_for(run)
        require(file_hash(log) == plan["report_journals"][run] and journal(log)[-1]["result"] == report
                and report["model"]["digest"] == plan["model_digest"], "Different original run")
        analysis = report["analysis"]
        claims = {c["id"]: c for c in analysis["claims"]}
        for probe in group["probes"]:
            cid, role = probe["claim"], probe["role"]
            c = claims[cid]
            require(digest(c) == probe["claim_sha256"] and
                    [[r["line"], r["end_line"]] for r in c["evidence"]] == probe["ranges"], "Different claim")
            yield run, probe, c, records, report["sample_sha256"], (
                cid in analysis["verdict_claim_ids"] and cid in analysis["verdict_support"][role])


def run_or_replay(live):
    plan = read(PLAN)
    require(file_hash(CONFIG) == plan["config_sha256"], "Different model configuration")
    cfg = read(CONFIG)
    if live:
        require(all(file_hash(ROOT / n) == h for n, h in plan["implementation"].items()), "Different candidate")
        model = OllamaClient(cfg)
        require(model.inspect()["digest"] == plan["model_digest"], "Different SLM")
        log = Journal(LOCAL)
        log.append("start", plan=file_hash(PLAN), model=plan["model_digest"])
    else:
        entries = iter(journal(LOCAL / "events.jsonl"))
        first = next(entries)
        require(first["event"] == "start" and first["plan"] == file_hash(PLAN)
                and first["model"] == plan["model_digest"], "Different evidence")
    rows = []
    for i, (run, probe, claim, records, sample, baseline) in enumerate(pairs(plan), 1):
        usage = {}

        def call(messages, schema, phase, evidence):
            if live:
                free = available_memory_bytes()
                if free is not None and free < cfg.get("minimum_free_ram_mb", 256) * 1024**2:
                    log.append("interrupted", pair=i, reason="low_memory")
                    raise RuntimeError("Memory floor reached")
                record_model_request(log, step=i, messages=messages, schema=schema, evidence=evidence, phase=phase)
                answer, measured = model.chat(messages, schema)
                log.append("response", step=i, answer=answer, metrics=measured)
            else:
                req, response = next(entries), next(entries)
                require(req["event"] == "model_request" and req["step"] == response["step"] == i
                        and req["messages"] == messages and req["schema"] == schema and req["phase"] == phase
                        and req["evidence"] == evidence and response["event"] == "response", "Different role inputs")
                answer, measured = response["answer"], response["metrics"]
            usage.update({k: measured[k] for k in ("latency_s", "prompt_tokens", "completion_tokens")})
            return answer

        decision = review_pair(claim, probe["role"], records, sample, call)
        row = {"run": run, "claim_sha256": probe["claim_sha256"], "expected": probe["expected"],
               "baseline": baseline, "usage": usage, **decision}
        if live:
            log.append("checked", row=row)
        else:
            entry = next(entries)
            require(entry["event"] == "checked" and entry["row"] == row, "Different replayed role decision")
        rows.append(row)
    if live:
        log.append("finished", count=len(rows))
    else:
        last = next(entries)
        require(last["event"] == "finished" and last["count"] == len(rows) and next(entries, None) is None,
                "Missing terminal result or unexpected events")
    return {"plan": file_hash(PLAN), "journal": file_hash(LOCAL / "events.jsonl"), "rows": rows}


def scores(data):
    result = {}
    for mode in ("baseline", "screened", "forced_review"):
        counts = dict(tp=0, fp=0, fn=0, tn=0)
        for row in data["rows"]:
            keep = row["status"] == "supported_by_review"
            chosen = row["baseline"] if mode == "baseline" else keep and (mode == "forced_review" or row["baseline"])
            key = ("tp" if row["expected"] else "fp") if chosen else ("fn" if row["expected"] else "tn")
            counts[key] += 1
        result[mode] = counts
    return result


def published():
    data, plan = read(PUBLIC), read(PLAN)
    require(data["plan"] == file_hash(PLAN), "Protocol differs")
    expected = []
    fixed = controls(plan)
    for group in fixed:
        run = group["run"]
        receipt = read(EVIDENCE / f"web-{run}.json")
        require(receipt["journal_sha256"] == plan["report_journals"][run]
                and receipt["model_digest"] == plan["model_digest"], "Public source differs")
        expected.extend((run, p["claim"], p["role"], p["claim_sha256"], p["expected"]) for p in group["probes"])
    require([(r["run"], r["claim"], r["role"], r["claim_sha256"], r["expected"]) for r in data["rows"]] == expected,
            "Control omitted or replaced")
    probes = [probe for group in fixed for probe in group["probes"]]
    for row, probe in zip(data["rows"], probes, strict=True):
        require(row["status"] in {"no_bound_send","unverified_citation","insufficient","source_over_budget","supported_by_review"}
                and type(row["baseline"]) is bool, "Invalid role assessment")
        if row["status"] == "supported_by_review":
            require([w["part"] for w in row["witnesses"]] == list(FIELDS[row["role"]]), "Incomplete role witness")
        for w in row["witnesses"]:
            require(any(a <= w["line"] <= b for a,b in probe["ranges"]), "Witness outside the claim")
    return data


def check_release():
    live = read(LIVE_RECEIPT)
    ref = read(EVIDENCE / f"web-{live['run']}.json")
    require(live["protocol"] == file_hash(PLAN) and live["journal"] == ref["journal_sha256"]
            and all(live[k] == ref[k] for k in ("run","status","verdict","metrics")), "Wrong live receipt")
    if live["status"] != "incomplete":
        checks = live["checks"]
        require(checks == ref["role_evidence_checks"] and [(x["role"],x["claim"]) for x in checks] ==
                [(k,id_) for k in SUPPORT_KEYS for id_ in live["proposed_roles"][k]], "Omitted live checks")
        require(all(live["kept_roles"][key] == [x["claim"] for x in checks if x["role"] == key and
                x["status"] == "supported_by_review"] for key in SUPPORT_KEYS), "Wrong accepted roles")
        opened = [{"role":d["role"], "claim":d["claim"], "status":d["status"],
                   "spans":[[w["line"],w["line"],w["output_sha256"]] for w in d["witnesses"]]} for d in checks]
        require(ref["role_lines_browser"] == {"run":live["run"],"screens":[{"width":w,"opened":opened} for w in (390,1360)],
                                             "errors":[],"external":[]}, "Different browser evidence")
    for case_row in read(NAVIGATION):
        run = case_row["run"]
        require(case_row["parent_journal"] == read(PLAN)["report_journals"][run]
                and [s["width"] for s in case_row["screens"]] == [390,1360]
                and case_row["screens"][0]["opened"] == case_row["screens"][1]["opened"]
                and not case_row["external"] and not case_row["errors"], "Other send navigation differs")
    return live


def web_results():
    rows = published()["rows"]
    judged = witness_audit(rows)
    result = []
    for group in controls(read(PLAN)):
        run = group["run"]
        cases = [r for r in rows if r["run"] == run]
        result.append({"run": run, "sample": read(EVIDENCE / f"web-{run}.json")["sample"],
                       "scores": scores({"rows":cases}), "pairs": len(cases),
                       "calls": sum(bool(r["usage"]) for r in cases),
                       "witness_audit": [dict(claim=d["claim"], role=d["role"], complete=d["complete"],
                                              reason=d["reason"]) for d in judged if d["run"] == run]})
    return result


def witness_audit(rows, *, verify_source=False):
    accepted = [r for r in rows if r["status"] == "supported_by_review"]
    labels = read(WITNESS_AUDIT)["rows"]
    require(len(accepted) == len(labels), "Not all accepted pairs were audited")
    for label, decision in zip(labels, accepted, strict=True):
        require(all(label[k] == decision[k] for k in ("claim","role","run","claim_sha256"))
                and [{k:v for k,v in w.items() if k != "line_sha256"} for w in label["witnesses"]] == decision["witnesses"]
                and type(label["complete"]) is bool and bool(label["reason"]), "Audit refers to a different witness")
        if verify_source:
            records = records_for(label["run"])
            for w in label["witnesses"]:
                rec = records[w["eid"]]
                require(w["output_sha256"] == rec["output_sha256"] and sha256(rec["line_map"][w["line"]].encode()).hexdigest()
                        == w["line_sha256"], "Wrong audited source line")
    return labels


def unused_sends():
    """Bind the exploratory web navigation to the old frozen report at both screen widths."""
    plan = read(PLAN)
    rows = []
    for group in controls(plan):
        run = group["run"]
        sites = case(run)["other_send_sites"]
        if not sites:
            continue
        expected = [{"claim":s["claim"], "fact":s["fact"],
                     "spans":[[r["line"],r["end"],r["output_sha256"]] for r in s["refs"]]} for s in sites]
        proof = read(ROOT / "evidence/local" / f"other-sends-{run}.json")
        require(proof == {"run":run, "screens":[{"width":w,"opened":expected} for w in (390,1360)],
                          "errors":[],"external":[]}, "Browser differs from the reviewed call and report")
        rows.append({**proof, "parent_journal":plan["report_journals"][run]})
    return rows


def verify_live(run):
    """Re-run the actual selection gate with the answers recorded at inference time."""
    plan = read(PLAN)
    candidates = []
    for folder in sorted((ROOT / "runs").glob("20*")):
        if RUN.fullmatch(folder.name):
            with (folder / "events.jsonl").open("rb") as stream:
                first = json.loads(stream.readline())
            if first["timestamp"] > plan["registered"] and first["sample"] == "public_mercurial.bin":
                candidates.append(folder.name)
    require(candidates and candidates[0] == run, "First subsequent Mercurial attempt missing")
    path = ROOT / "runs" / run / "events.jsonl"
    events = journal(path)
    receipt = read(EVIDENCE / f"web-{run}.json")
    require(file_hash(path) == receipt["journal_sha256"] and events[-1]["event"] == "run_finished"
            and events[-1]["result"] == read(path.parent / "report.private.json")
            and receipt["model_digest"] == plan["model_digest"], "Different completed record")
    manifest = next(e["files"] for e in events if e["event"] == "source_version")
    require(all(manifest.get(n) == h for n,h in plan["implementation"].items()), "Wrong revision")
    analysis = events[-1]["result"]["analysis"]
    result = {"run":run,"protocol":file_hash(PLAN),"journal":file_hash(path),"status":receipt["status"],
              "verdict":receipt["verdict"],"metrics":receipt["metrics"],"checks":[]}
    if "role_checks" not in analysis:
        require(receipt["status"] == "incomplete","Missing screening on completed report")
        return result
    kept, checks, calls = replay_screen(run, events, analysis, receipt["sha256"])
    require(checks == analysis["role_checks"] == receipt["role_evidence_checks"]
            and kept == analysis["verdict_support"], "Role projection differs from the source")
    return {**result, "checks":checks, "proposed_roles":analysis["proposed_roles"], "kept_roles":kept,
            "review_calls":calls,"proposed_verdict":analysis["proposed_verdict"]}


def replay_screen(run, events, analysis, sha, *, require_link_read=False):
    response, = [e["action"] for e in events if e["event"] == "model_response" and e.get("phase") == "card_verdict"]
    require(all(response[k] == analysis["proposed_roles"][k] for k in SUPPORT_KEYS), "Different original roles")
    trace = iter(e for e in events if e.get("phase") == "verdict_role_evidence"
                 or e["event"] in ("verdict_role_checked", "link_source_checked"))
    calls = []

    def call(messages, schema, phase, exposure):
        request, reply = next(trace), next(trace)
        require(request["event"] == "model_request" and request["phase"] == phase
                and request["messages"] == messages and request["schema"] == schema and request["evidence"] == exposure
                and reply["event"] == "model_response" and reply["step"] == request["step"], "Different live source")
        calls.append({k:reply["metrics"][k] for k in ("latency_s","prompt_tokens","completion_tokens")})
        return reply["action"]

    class Decisions:
        def append(self, kind, **data):
            entry = next(trace)
            require(entry["event"] == kind and all(entry[k] == v for k,v in data.items()), "Different live decision")

    kept, checks = screen(analysis["proposed_roles"], response["verdict_claim_ids"], analysis["claims"],
                          records_for(run), sha, call, Decisions(), require_link_read=require_link_read)
    require(next(trace,None) is None, "Unconsumed role decisions")
    return kept, checks, calls


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--replay", action="store_true")
    mode.add_argument("--verify-live-run", metavar="RUN")
    args = parser.parse_args()
    if args.live:
        recorded = run_or_replay(True)
        require(recorded == run_or_replay(False), "Live inference differs from replay")
        dump_json(PUBLIC, recorded)
    if args.verify_live_run:
        dump_json(LIVE_RECEIPT, verify_live(args.verify_live_run))
    data = published()
    if not args.live:
        live = check_release()
        witness_audit(data["rows"], verify_source=args.replay)
    if args.replay:
        require(data == run_or_replay(False), "Private and public results differ")
        require(live == verify_live(live["run"]) and unused_sends() == read(NAVIGATION), "Live or browser replay differs")
    print(json.dumps(scores(data)))
