"""Run bounded read-only ILSpy lookups on registered Microsoft control files in the isolated VM."""
import argparse
from hashlib import sha256
import json
from pathlib import PureWindowsPath

from eval.table_access_study import file_hash
from eval.transfer_report_audit import require
from eval.web_report_quality import ROOT, EVIDENCE, read
from lab_web.cases import absorb
from stealer_agent.journal import Journal, dump_json, verify_journal
from stealer_agent.model_projection import ModelEvidenceView
from stealer_agent.operation_context import valid_operations
from stealer_agent.security import guard_observation
from stealer_agent.transport import ToolClient

MANIFEST = ROOT / "eval/corpora/real-yara-development-v3.json"
TRIAL = ROOT / "private/catch-controls/first"
PUBLIC = EVIDENCE / "catch-clean-controls.json"
QUERIES = (".Message", "catch (")


def controls():
    manifest = read(MANIFEST)
    negatives = {r["sample"]:r["sha256"] for r in manifest["corpora"]["holdout"] if r["positive"] is False}
    rows = sorted((r for r in manifest["source_manifest"]["rows"]
                  if r.get("positive") is False and r.get("signature_status") == "Valid"
                  and "Microsoft Corporation" in r["publisher"] and "Microsoft.NET" in PureWindowsPath(r["source_path"]).parts
                  and negatives.get(r["sample"]) == r["sha256"]), key=lambda r: r["sample"])
    require(len(rows) >= 5, "Missing signed controls")
    return rows[:5]


def collect():
    cfg = read(ROOT / "config/host.investigation.example.json")
    client = ToolClient(cfg, (ROOT / "config/lab.token").read_text(encoding="utf-8-sig").strip())
    vm = client.inspect()
    lab = read(ROOT / "evidence/local/lab-verification.json")
    require(lab["source_matches_vm"] and lab["host_source"]["vm_tools/catch_arguments.py"] ==
            file_hash(ROOT / "vm_tools/catch_arguments.py"), "Wrong VM source revision")
    rows = controls()
    log = Journal(TRIAL)
    log.append("start", files=[r["sample"] for r in rows], corpus=file_hash(MANIFEST), queries=list(QUERIES),
               parser=lab["host_source"]["vm_tools/catch_arguments.py"], isolation=vm["isolation"]["checks"])
    for row in rows:
        try:
            for query in (None, *QUERIES):
                action = "search_evidence" if query else "decompile_dotnet"
                args = {"sample": row["sample"]}
                if query:
                    args.update(evidence_id=eid, query=query)
                log.append("dispatch", action=action, arguments=args)
                obs = client.call(action, args)
                require(obs.get("sample_sha256") == row["sha256"] and obs.get("sample") == row["sample"], "Control hash mismatch")
                log.append("observation", source=obs)
                if obs["status"] != "ok":
                    break
                if query is None:
                    eid = obs["evidence_id"]
        except (OSError, ValueError, RuntimeError) as exc:
            log.append("failed", sample=row["sample"], error=type(exc).__name__)
    log.append("finished", files=len(rows))


def replay():
    path = TRIAL / "events.jsonl"
    verify_journal(path)
    events = list(map(json.loads,path.read_bytes().splitlines()))
    controls_by_name = {r["sample"]: r for r in controls()}
    start = events[0]
    require(start["event"] == "start" and start["files"] == list(controls_by_name) and start["corpus"] == file_hash(MANIFEST)
            and start["queries"] == list(QUERIES) and events[-1]["event"] == "finished", "Unexpected control protocol")
    rows, sample = [], None
    for e in events[1:-1]:
        if e["event"] == "dispatch":
            args = e["arguments"]
            if e["action"] == "decompile_dotnet":
                sample = args["sample"]
                records, view = {}, ModelEvidenceView()
                result = {"sample":sample, "sha256":controls_by_name[sample]["sha256"], "status":"pending", "hits":[], "sites":[]}
                rows.append(result)
            else:
                require(args == {"sample":sample,"evidence_id":eid,"query":QUERIES[len(result["hits"])]}, "Wrong lookup")
        elif e["event"] == "failed":
            result.update(status="failed",error=e["error"])
        else:
            require(e["event"] == "observation", "Unexpected control event")
            o = e["source"]
            require(o["sample"] == sample and o["sample_sha256"] == result["sha256"], "Wrong control")
            if o["status"] != "ok":
                result["status"] = "tool_error"
                if e["source"]["tool"] == "decompile_dotnet" and any(
                    row.get("text") == "ValueError: Sample is not identified as a managed PE"
                    for row in o["lines"]
                ):
                    result["reason"] = "not_managed_pe"
                continue
            require(o["tool"] == "decompile_dotnet", "Different tool")
            if "query" not in args:
                eid = o["evidence_id"]
                result["source_sha256"] = o["output_sha256"]
            else:
                require(o["search_query"] == args["query"] and o["output_sha256"] == result["source_sha256"]
                        and o["evidence_id"] == eid, "Search escaped control")
                result["hits"].append(o["hit_count"])
            absorb(records,view.observation(guard_observation(o)[0]))
            view.refresh(records)
            result["sites"] = [{"fact":f["fact_id"],"spans":[[r["line"],r["end_line"]] for r in f["ranges"]]}
                               for f in valid_operations(records[eid]) if f["operation"] == "catch_message_argument"]
            result["status"] = "complete" if len(result["hits"]) == len(QUERIES) else "partial"
    require([r["sample"] for r in rows] == start["files"], "Omitted control")
    return {"journal_sha256":sha256(path.read_bytes()).hexdigest(), "corpus_sha256":start["corpus"], "queries":start["queries"],
            "parser_sha256":start["parser"], "isolation":start["isolation"], "controls":rows}


def published():
    data = read(PUBLIC)
    require(data["corpus_sha256"] == file_hash(MANIFEST) and data["queries"] == list(QUERIES)
            and data["parser_sha256"] == read(ROOT / "eval/adjudications/catch-argument-protocol.json")["core"]["vm_tools/catch_arguments.py"]
            and [(r["sample"],r["sha256"]) for r in data["controls"]] == [(r["sample"],r["sha256"]) for r in controls()]
            and all(data["isolation"].get(k) is True for k in ("vm_hardware","no_default_gateway","operator_attestations")),
            "Different controls or isolation")
    for r in data["controls"]:
        require(r["status"] in {"complete","partial","failed","tool_error"}
                and ("reason" not in r or (r["status"] == "tool_error" and r["reason"] == "not_managed_pe"))
                and (r["status"] != "complete" or len(r["hits"]) == 2)
                and all(type(n) is int and n >= 0 for n in r["hits"])
                and all(s["spans"] and all(0 < a <= b for a,b in s["spans"]) for s in r["sites"]), "Invalid control result")
    return data


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--collect", action="store_true")
    cli.add_argument("--replay", action="store_true")
    args = cli.parse_args()
    if args.collect:
        collect()
        dump_json(PUBLIC,replay())
    result = published()
    if args.replay:
        require(result == replay(), "Private control observations differ")
    print([(r["sample"],r["status"],r["hits"],len(r["sites"])) for r in result["controls"]])
