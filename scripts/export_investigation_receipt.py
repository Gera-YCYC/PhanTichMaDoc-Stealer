"""Publish only provenance, counts, decisions and coordinates for a verified web investigation."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_web.cases import ROOT, case, directory, read
from eval.stability import claim_key
from scripts.report_experiment_receipt import config_digest
from stealer_agent.journal import canonical, dump_json, verify_journal
from stealer_agent.investigation import checked_argument


def argument_clicks(view, events, records, clicks):
    edge, = (e for e in view["graph"]["edges"] if e["id"] == "rows-process")
    proof = edge["argument_check"]
    eid = proof["refs"][0]["eid"]
    rec = records[eid]
    spans = [[r["line"], r["end"], r["output_sha256"]] for r in proof["refs"]]
    if (edge["status"] != "supported" or checked_argument(rec, view["sha"]) != proof
            or clicks["run"] != view["run"] or clicks["spans"] != spans
            or any(clicks[k] != proof[k] for k in ("roles", "index", "position"))
            or clicks["errors"] or clicks["external"]):
        raise ValueError("Browser did not reproduce the bound VM result")
    screens = [{"width": w, "graph_spans": len(spans), "report_spans": len(spans)} for w in (390, 1360)]
    if clicks["screens"] != screens:
        raise ValueError("Incomplete browser coverage")
    group = "claims" if clicks["retained"] else "rejected_claims"
    claim, = (c for c in view[group] if c["id"] == clicks["claim"])
    if [(r["eid"], r["line"], r["end"]) for r in claim["refs"]] != [
            (r["eid"], r["line"], r["end"]) for r in proof["refs"]]:
        raise ValueError("Report cites different locations")
    observed = next(e for e in events if e["event"] == "observation"
                    and e["model_visible"].get("row_use") == rec["row_use"])
    trace = {e["event"]: e for e in events if e.get("step") == observed["step"]}
    start, action, end = (trace[k] for k in ("hypothesis_open", "action_dispatched", "hypothesis_result"))
    if not (start["edge"] == end["edge"] == edge["id"] and edge["id"] not in start["supported"]
            and action["action"] == "search_evidence" and action["arguments"].get("verify_row_use") is True
            and action["arguments"]["evidence_id"] == eid and end["status"] == "supported"
            and start["sequence"] < action["sequence"] < observed["sequence"] < end["sequence"]):
        raise ValueError("Missing live search or status transition")
    return {"step": observed["step"], "backend": rec["row_use"]["backend"],
            "proof_id": rec["row_use"]["proof_id"], "rows_sha256": rec["row_use"]["rows_sha256"],
            "roles": proof["roles"], "index_zero_based": proof["index"], "argument_zero_based": proof["position"],
            "spans": spans, "screens": screens, "claim": claim["id"], "retained": clicks["retained"]}


def export(run):
    folder = directory(run)
    view = case(run)
    path = folder / "events.jsonl"
    count = verify_journal(path)
    events = list(map(json.loads, path.read_bytes().splitlines()))
    report = events[-1]["result"]
    if (
        report["sample_sha256"] != view["sha"]
        or not report["acceptance"]["model_minimum_met"]
    ):
        raise ValueError("Incomplete public-run provenance")
    pre = next(e for e in events if e["event"] == "preflight")
    src = next(e for e in events if e["event"] == "source_version")
    stored = report.get("investigation")
    if not stored:
        raise ValueError("Run has no terminal investigation ledger")

    def project(graph):
        return [
            {
                "id": e["id"],
                "status": e["status"],
                **(
                    {
                        "path_check": {
                            "relation": e["path_check"]["relation"],
                            "possible_names": e["path_check"]["component_count"],
                            "unresolved": e["path_check"]["unresolved"],
                            "spans": [
                                [r["line"], r["end"], r["output_sha256"]]
                                for r in e["path_check"]["refs"]
                            ],
                        }
                    }
                    if e.get("path_check")
                    else {}
                ),
                "coordinates": [
                    {"eid": r["eid"], "line": r["line"], "end": r["end"]}
                    for r in e.get("trail") or e["refs"]
                ],
            }
            for e in graph["edges"]
        ]

    questions = []
    for p in sorted(folder.glob("questions/q_*/events.jsonl")):
        n = verify_journal(p)
        qs = list(map(json.loads, p.read_bytes().splitlines()))
        if qs[0]["run"] != run or qs[0]["sample_sha256"] != view["sha"]:
            raise ValueError("Unbound question")
        questions.append(
            {
                "id": p.parent.name,
                "events": n,
                "journal_sha256": sha256(p.read_bytes()).hexdigest(),
                "topic": next(
                    (e["topic"] for e in qs if e["event"] == "topic_selected"), None
                ),
                "search_calls": sum(e["event"] == "action_dispatched" for e in qs),
                "search_errors": sum(e["event"] == "tool_error" for e in qs),
                "search_hits": [
                    e["hit_count"] for e in qs if e["event"] == "observation"
                ],
                "source_refs": len(qs[-1].get("answer", {}).get("refs", [])),
                "related_locations": len(
                    qs[-1].get("answer", {}).get("related_locations", [])
                ),
                "status": qs[-1]["event"],
                **(
                    {
                        "opened_anchors": [
                            e["opened_anchors"] for e in qs if "opened_anchors" in e
                        ]
                    }
                    if any("opened_anchors" in e for e in qs)
                    else {}
                ),
            }
        )
        selected = next((e for e in qs if e["event"] == "topic_selected"), {})
        if selected.get("origin") == "map_field":
            clicks_file = ROOT / "evidence/local" / f"schema-{p.parent.name}.json"
            if clicks_file.is_file():
                field, = (f for f in view["reader_fields"] if f["id"] == selected["field"] and f["ordinal"])
                answer = qs[-1]["answer"]
                search = answer["search"]
                observed, = (e for e in qs if e["event"] == "observation")
                action, = (e for e in qs if e["event"] == "action_dispatched")
                digest = field["refs"][0]["output_sha256"]
                location = field["refs"][-1]["line"]
                eid = field["refs"][0]["eid"]
                query = action["arguments"]["query"]
                expected = {"run": run, "journal": p.parent.name, "field": field["id"], "source_sha256": digest,
                            "hits": observed["hit_count"], "field_spans": [[r["line"], r["end"]] for r in field["refs"]],
                            "locations": [[r["line"], r["end"], digest] for r in search["refs"]], "errors": [], "external": []}
                if (read(clicks_file) != expected or qs[0]["model"] != pre["model"]["digest"]
                        or qs[0]["question"] != f"Có căn cứ đặt tên cột số ở dòng {location} không?"
                        or answer["topic"] != "reader_schema" or search["status"] != "ok" or answer["refs"] != field["refs"]
                        or action["action"] != "search_evidence" or query not in ("CREATE TABLE", "table_info", "sqlite_master")
                        or action["arguments"] != {"sample":view["sample"], "evidence_id":eid, "query":query}
                        or not selected["sequence"] < action["sequence"] < observed["sequence"] < qs[-1]["sequence"]
                        or observed["output_sha256"] != digest or search["output_sha256"] != digest
                        or observed["evidence_id"] != eid or search["hit_count"] != observed["hit_count"]
                        or [r["line"] for r in search["refs"]] != observed["opened_anchors"]):
                    raise ValueError("Browser field differs from the question or VM source")
                questions[-1]["schema_search"] = {**expected, "literal":query}
        if selected.get("origin") == "map_edge":
            clicks_file = ROOT / "evidence/local" / f"focus-{p.parent.name}.json"
            if clicks_file.is_file():
                clicks = read(clicks_file)
                edge, = (e for e in view["graph"]["edges"] if e["id"] == selected["topic"])
                answer = qs[-1]["answer"]
                search = answer["search"]
                observed, = (e for e in qs if e["event"] == "observation")
                dispatched, = (e for e in qs if e["event"] == "action_dispatched")
                spans = [[r["line"], r["end"]] for r in search["refs"]]
                expected = {"run": run, "edge": edge["id"], "journal": p.parent.name,
                            "hits": search["hit_count"], "spans": spans, "opened": int(bool(spans)),
                            "source_sha256": search["output_sha256"], "errors": [], "external": []}
                if (clicks != expected or qs[0]["model"] != pre["model"]["digest"]
                        or qs[0]["question"] != f"Bằng chứng nào nối hai bước {edge['label']}?"
                        or edge["status"] == "supported" or selected["topic"] != answer["topic"]
                        or search["status"] != "ok" or dispatched["action"] != "search_evidence"
                        or not selected["sequence"] < dispatched["sequence"] < observed["sequence"] < qs[-1]["sequence"]
                        or search["output_sha256"] != observed["output_sha256"]
                        or search["hit_count"] != observed["hit_count"]
                        or [a for a, _ in spans] != observed["opened_anchors"]):
                    raise ValueError("Browser focus differs from the selected edge or live VM search")
                questions[-1]["map_click"] = expected
    browser = {}
    reviews = []
    for claim in view["rejected_claims"]:
        display = claim.get("revisit")
        if not display:
            continue
        child = folder / "claim-reviews" / display["id"] / "events.jsonl"
        verify_journal(child)
        logged = list(map(json.loads, child.read_bytes().splitlines()))
        first, last = logged[0], logged[-1]
        replies = [e for e in logged if e["event"] == "model_response"]
        if not (
            last["event"] == "review_finished"
            and last["display"] == display
            and first["parent"] == display["claim"] == claim["id"]
            and first["source_journal_sha256"] == sha256(path.read_bytes()).hexdigest()
            and display["model_calls"] == len(replies)
        ):
            raise ValueError("Follow-up review differs from the original case")
        reviews.append(
            {
                "id": display["id"],
                "parent_claim": claim["id"],
                "decision": display["decision"],
                "model_calls": len(replies),
                "journal_sha256": sha256(child.read_bytes()).hexdigest(),
                "original_request_sha256": first["original_request_sha256"],
                "source_ranges": [[r["line"], r["end"]] for r in display["refs"]],
            }
        )
    clicks_file = ROOT / "evidence/local" / f"staging-{run}.json"
    if clicks_file.exists():
        clicks = read(clicks_file)
        if clicks.get("opened"):
            qid = clicks["question_journal"]
            (receipt,) = [
                q for q in questions if q["id"] == qid and q["status"] == "answered"
            ]
            trace = folder / "questions" / qid / "events.jsonl"
            answer = json.loads(trace.read_bytes().splitlines()[-1])["answer"]
            (edge,) = [e for e in stored["edges"] if e["id"] == "write-archive"]
            spans = [
                [r["line"], r["end"], r["output_sha256"]]
                for r in edge["path_check"]["refs"]
            ]
            found = [
                [r["line"], r["end"], r["output_sha256"]]
                for r in answer["search"]["refs"]
            ]
            if not (
                clicks["run"] == run
                and clicks["topic"] == answer["topic"] == "write-archive"
                and clicks["width"] == 390
                and not clicks["errors"]
                and not clicks["external"]
                and spans == clicks["spans"]
                and found == clicks["opened"]
                and answer["refs"] == edge["path_check"]["refs"]
                and clicks["answer_refs"] == len(spans)
                and receipt["opened_anchors"] == [[n for n, _, _ in found]]
                and receipt["search_hits"] == [clicks["search_hits"]]
                and receipt["search_errors"] == 0
            ):
                raise ValueError(
                    "Browser excerpts differ from the VM, question or graph"
                )
            browser = {
                "staging_browser": {
                    "question": qid,
                    "question_journal_sha256": receipt["journal_sha256"],
                    "width": clicks["width"],
                    "graph_spans_opened": len(spans),
                    "search_spans_opened": found,
                }
            }
    argument_file = ROOT / "evidence/local" / f"argument-web-{run}.json"
    if argument_file.is_file():
        from lab_web.cases import records_for
        clicks = read(argument_file)
        proof = argument_clicks(view, events, records_for(run), clicks)
        if qid := clicks.get("question"):
            question, = (q for q in questions if q["id"] == qid and q["status"] == "answered")
            trace = list(map(json.loads, (folder / "questions" / qid / "events.jsonl").read_bytes().splitlines()))
            answer = trace[-1]["answer"]
            expected = [[r["line"], r["end"], r["output_sha256"]] for r in answer["refs"]]
            if not (question["topic"] == "rows-process" and question["search_calls"] == 0
                    and trace[0]["model"] == pre["model"]["digest"] and expected == proof["spans"]):
                raise ValueError("Question differs from the checked source")
            proof["question_journal_sha256"] = question["journal_sha256"]
        browser["argument_browser"] = proof
    ordinal_file = ROOT / "evidence/local" / f"ordinal-web-{run}.json"
    catch_file = ROOT / "evidence/local" / f"catch-web-{run}.json"
    if catch_file.is_file():
        clicks = read(catch_file)
        opened = [{"fact": site["id"], "claim": site["claim"], "overlapping":site["overlapping_claims"],
                   "spans": [[r["line"], r["end"], r["output_sha256"]] for r in site["refs"]]}
                  for site in view["catch_sites"]]
        edges = view["graph"]["edges"]
        stop = next(i for i, edge in enumerate(edges) if edge["id"] == "message-send")
        target = next((e for e in edges[:stop + 1] if e["status"] != "supported"), edges[stop])
        expected = {"run": run, "screens": [{"width": w, "opened": opened, "verdict_edge": target["id"]} for w in (390,1360)],
                    "errors": [], "external": []}
        if clicks != expected:
            raise ValueError("Browser sources differ from the catch argument in the journal")
        browser["catch_sites_browser"] = clicks
    if ordinal_file.is_file():
        clicks = read(ordinal_file)
        plan = read(ROOT / "eval/adjudications/ordinal-review-protocol.json")
        parent = case(plan["baseline"])
        c2, = (c for c in parent["claims"] if c["id"] == "C2")
        fields = {entry["claim"] for field in view["reader_fields"] for entry in field["reviews"]}
        spans = [[r["line"], r["end"], parent["cited_windows"][f"{r['eid']}:{r['line']}:{r['end']}"]["output_sha256"]]
                 for r in c2["refs"]]
        expected = [{"width": w, "ids": sorted(fields), "paired_claim": "C2",
                     "paired_run": parent["run"], "paired_spans": spans} for w in (390, 1360)]
        if not fields or clicks != {"run": run, "opened": expected, "errors": [], "external": []}:
            raise ValueError("Browser clicks differ from the column reviews or the paired source")
        browser["ordinal_columns_browser"] = clicks
    checks = (view["verdict_trace"] or {}).get("checks")
    recovery = (view["verdict_trace"] or {}).get("send_recovery")
    if recovery is not None:
        browser["send_recovery"] = recovery
        browser["evidence_kind"] = report["evidence_kind"]
        browser["report_method"] = report["analysis"]["report_method"]
        if browser["report_method"] == "evidence-cards/17":
            browser["link_sources"] = view["link_sources"]
        browser["support_after_recovery"] = report["analysis"]["verdict_support"]
        budget = [e for e in events if e["event"] == "send_citation_budget"]
        if budget:
            entry, = budget
            browser["send_citation_budget"] = {k:entry[k] for k in ("eligible","reserved")}
        click_file = ROOT / "evidence/local" / f"send-recovery-web-{run}.json"
        if click_file.is_file():
            opened = [{"claim":site["claim"], "fact":site["fact"], **ref}
                      for site in recovery["sites"] for ref in site["refs"]]
            expected = {"run":run, "screens":[{"width":w,"opened":opened} for w in (390,1360)],
                        "errors":[], "external":[]}
            if view.get("link_sources"):
                ids = {s["claim"] for s in view["link_sources"]}
                rows = [{"claim":c["claim"], "status":c["status"], "lines":[w["line"] for w in c["witnesses"]]}
                        for c in checks if c["role"] == "data_link_claim_ids" and c["claim"] in ids]
                for screen in expected["screens"]:
                    screen["linkAudits"] = rows
            if read(click_file) != expected:
                raise ValueError("Các dòng mở trên web khác nguồn của thao tác gửi.")
            browser["send_recovery_browser"] = expected
    if checks is not None:
        browser["role_evidence_checks"] = checks
        proof_file = ROOT / "evidence/local" / f"role-lines-web-{run}.json"
        if proof_file.is_file():
            opened = [{"role": d["role"], "claim": d["claim"], "status": d["status"],
                       "spans": [[w["line"], w["line"], w["output_sha256"]] for w in d["witnesses"]]} for d in checks]
            proof = read(proof_file)
            if proof != {"run": run, "screens": [{"width": w, "opened": opened} for w in (390,1360)],
                         "errors": [], "external": []}:
                raise ValueError("Browser role evidence differs from the terminal journal")
            browser["role_lines_browser"] = proof
    return {
        **({"termination": view["termination"]} if view["termination"] else {}),
        **browser,
        **({"latest_followup_reviews": reviews} if reviews else {}),
        "run": run,
        "sample": view["sample"],
        "sha256": view["sha"],
        "model": view["model"],
        "model_digest": pre["model"]["digest"],
        "source_manifest_sha256": src["manifest_sha256"],
        "config_sha256_excluding_sample": config_digest(
            next(e["config"] for e in events if e["event"] == "run_started")
        ),
        **(
            {"staging_parser_sha256": src["files"]["vm_tools/staging_link.py"]}
            if "vm_tools/staging_link.py" in src["files"]
            else {}
        ),
        "current_logic_matches_run": all(
            (ROOT / k).is_file() and sha256((ROOT / k).read_bytes()).hexdigest() == v
            for k, v in src["files"].items()
        ),
        "vm_isolation": pre["vm"]["isolation"]["checks"],
        "status": view["status"],
        "verdict": view["verdict"],
        "metrics": view["metrics"],
        "tools": report["successful_tools"],
        "journal_events": count,
        "journal_sha256": sha256(path.read_bytes()).hexdigest(),
        "gaps": [
            {k: e[k] for k in ("step", "edge", "status", "hit_count") if k in e}
            for e in events
            if e["event"] in ("hypothesis_open", "hypothesis_result")
        ],
        "accepted_claims": len(view["claims"]),
        "accepted_claim_keys_sha256": sha256(
            canonical(
                sorted(
                    sha256(canonical(claim_key(c))).hexdigest()
                    for c in report["analysis"]["claims"]
                )
            )
        ).hexdigest(),
        "terminal_edges": project(stored),
        "display_graph_origin": view["graph_origin"],
        "displayed_edges_match_terminal": project(view["graph"]) == project(stored),
        "yara": view["yara"],
        "questions": questions,
        "ranking_anchors_for_review": len(view["anchors"]),
        "limits": [
            "Static development run. An evidence link is not runtime delivery.",
            "current_logic_matches_run compares the run's core source manifest to the local core at export; the UI can be revised independently.",
            "Coordinates and counts only. No raw source, model messages or secret values exported.",
        ],
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--run", required=True)
    args = p.parse_args()
    result = export(args.run)
    out = ROOT / "deliverables/real-demo-evidence" / ("web-" + args.run + ".json")
    dump_json(out, result)
    print(out.name)
