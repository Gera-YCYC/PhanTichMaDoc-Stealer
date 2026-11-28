"""Publish only provenance, counts, decisions and coordinates for a verified web investigation."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lab_web.cases import ROOT, case, directory, read
from stealer_agent.journal import dump_json, verify_journal


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
                "search_hits": [
                    e["hit_count"] for e in qs if e["event"] == "observation"
                ],
                "source_refs": len(qs[-1].get("answer", {}).get("refs", [])),
                "related_locations": len(
                    qs[-1].get("answer", {}).get("related_locations", [])
                ),
                "status": qs[-1]["event"],
            }
        )
    return {
        "run": run,
        "sample": view["sample"],
        "sha256": view["sha"],
        "model": view["model"],
        "model_digest": pre["model"]["digest"],
        "source_manifest_sha256": src["manifest_sha256"],
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
