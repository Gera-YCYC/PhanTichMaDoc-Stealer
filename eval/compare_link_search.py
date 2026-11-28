"""Paired live comparison of evidence navigation, with an identical VM seed in both arms."""

import argparse
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import time
from uuid import uuid4
from lab_web.cases import ROOT, absorb, read, samples
from lab_web.review import choose
from stealer_agent.investigation import ledger, options
from stealer_agent.journal import Journal, dump_json, utc_now
from stealer_agent.model_projection import ModelEvidenceView
from stealer_agent.security import guard_observation
from stealer_agent.transport import OllamaClient, ToolClient

FIXED = ("SELECT", "sendmail", "UploadFile", "GetString")
CASES = ("public_gomorrah.bin", "public_python2024.bin")


def reference(sample):
    folder = ROOT / "eval/reference_units"
    if sample == CASES[0]:
        doc = read(folder / "gomorrah.atomic-v1.json")
        pairs = {
            (
                "send-response",
                u["source_references"][-2]["line"],
                u["source_references"][-1]["line"],
            ): u["id"]
            for u in doc["units"]
            if u["id"].endswith("-ascii")
        }
        return doc["source_references"][0]["output_sha256"], pairs
    doc = read(folder / "python2024.behavior-v1.json")
    return doc["source_record"]["output_sha256"], {
        ("query-rows", 142, 143): "PY24-U03",
        ("query-rows", 167, 168): "PY24-U06",
        ("message-send", 103, 109): "PY24-U12",
    }


def prepare(vm, sample, log):
    digest = samples()[sample]["sha256"]

    def call(name, **kw):
        o = vm.call(name, {"sample": sample, **kw})
        if (
            o.get("sample") != sample
            or o.get("sample_sha256") != digest
            or o.get("tool") != name
        ):
            raise ValueError("VM sample or tool identity mismatch")
        log.append(
            "prepare", tool=name, status=o["status"], evidence_id=o["evidence_id"]
        )
        return o

    call("identify")
    if sample == CASES[0]:
        o = call("decompile_dotnet")
    else:
        import json

        unpack = call("unpack_pyinstaller")
        inventory = json.loads("".join(r["text"] for r in unpack["lines"]))
        idx = next(
            e["entry_index"] for e in inventory["entries"] if e["application_entry"]
        )
        o = call("decompile_python", entry_index=idx)
        if o["status"] != "ok":
            o = call("disassemble_python", entry_index=idx)
        o = call("decode_python_literals", evidence_id=o["evidence_id"])
    matches = o["output_sha256"] == reference(sample)[0]
    if o["status"] == "ok" and sample == CASES[1] and not matches:
        # Decoded-source headers include the fresh input evidence ID. Verify the
        # VM parser's normalized source hash before using its reference positions.
        check = vm.call(
            "search_evidence",
            {"sample": sample, "query": "SELECT", "evidence_id": o["evidence_id"]},
        )
        expected = read(ROOT / "eval/reference_units/python2024.behavior-v1.json")[
            "source_record"
        ]["parser_source_sha256"]
        matches = (
            check.get("output_sha256") == o["output_sha256"]
            and check.get("sample_sha256") == digest
            and check.get("evidence_id") == o["evidence_id"]
            and check.get("syntax_context", {}).get("source_sha256") == expected
        )
        log.append(
            "source_binding",
            normalized_source_sha256=expected,
            matched=matches,
            tool="search_evidence",
            excluded_from_both_arms=True,
        )
    if o["status"] != "ok" or not matches:
        raise ValueError(
            "Recovered source differs from the frozen grading coordinates."
        )
    return o


def grade(graph, targets):
    got = set()
    for edge in graph["edges"]:
        refs = edge["refs"]
        for a, b in zip(refs[::2], refs[1::2]):
            got.add((edge["id"], a["line"], b["line"]))
    right = got & targets.keys()
    # Available references cover specific sites, not every syntactically true flow.
    # Score precision only for predictions ending at graded sites (including wrong producers).
    sites = {(k, c) for k, _, c in targets}
    wrong = [t for t in got - right if (t[0], t[2]) in sites]
    return {
        "covered": sorted(targets[t] for t in right),
        "missed": sorted(targets[t] for t in targets.keys() - got),
        "wrong_producer_at_graded_site": len(wrong),
        "ungraded_other_sites": len(got) - len(right) - len(wrong),
        "site_precision": len(right) / (len(right) + len(wrong))
        if right or wrong
        else None,
        "site_recall": len(right) / len(targets),
    }


def experiment():
    cfg = read(ROOT / "config/host.investigation.example.json")
    vm = ToolClient(cfg, (ROOT / "config/lab.token").read_text().strip())
    model = OllamaClient({**cfg, "num_predict": 90})
    vm.inspect()
    info = model.inspect()
    log = Journal(ROOT / "runs" / ("link_compare_" + uuid4().hex[:12]))
    outputs = []
    for index, sample in enumerate(CASES):
        seed = prepare(vm, sample, log)
        for mode in ("fixed", "adaptive") if index == 0 else ("adaptive", "fixed"):
            view = ModelEvidenceView()
            records = {}
            absorb(records, view.observation(guard_observation(deepcopy(seed))[0]))
            used = set()
            actions = []
            started = time.perf_counter()
            for fixed in FIXED:
                gap = None
                if mode == "adaptive":
                    gap, qs = options(
                        ledger(records, seed["sample_sha256"]),
                        used,
                        tool=seed["tool"],
                        record=records[seed["evidence_id"]],
                    )
                    if not qs:
                        break
                    q, usage = choose(
                        model,
                        "Select one allowed static search for the unresolved link.",
                        {"hypothesis": gap, "candidates": qs, "previous": sorted(used)},
                        qs,
                    )
                else:
                    q = fixed
                    usage = None
                used.add(q.casefold())
                o = vm.call(
                    "search_evidence",
                    {"sample": sample, "query": q, "evidence_id": seed["evidence_id"]},
                )
                if (
                    o.get("status") != "ok"
                    or o.get("search_query") != q
                    or any(
                        o.get(k) != seed[k]
                        for k in (
                            "evidence_id",
                            "sample_sha256",
                            "tool",
                            "output_sha256",
                            "sample",
                        )
                    )
                ):
                    raise ValueError(
                        "Live navigation returned an invalid source binding"
                    )
                obs = view.observation(guard_observation(o)[0])
                absorb(records, obs)
                view.refresh(records)
                actions.append(
                    {
                        "gap": gap,
                        "query": q,
                        "hits": o["hit_count"],
                        "model_usage": usage,
                    }
                )
                log.append(
                    "query",
                    mode=mode,
                    sample=sample,
                    action=actions[-1],
                    model_visible=obs,
                )
            result = {
                "mode": mode,
                "sample": sample,
                "sample_sha256": seed["sample_sha256"],
                "output_sha256": seed["output_sha256"],
                "elapsed_s": round(time.perf_counter() - started, 3),
                "tool_calls": len(actions),
                "model_calls": sum(a["model_usage"] is not None for a in actions),
                "actions": actions,
                **grade(ledger(records, seed["sample_sha256"]), reference(sample)[1]),
            }
            outputs.append(result)
            print(sample, mode, result["site_recall"], flush=True)
    log.append("finished", results=outputs)
    return {
        "run": log.directory.name,
        "time": utc_now(),
        "model": cfg["model"],
        "model_digest": info["digest"],
        "same_seed_per_pair": True,
        "search_budget_per_arm": len(FIXED),
        "fixed_queries": FIXED,
        "scope": "Search stage only. Development samples and ten annotated source links. Other sites ungraded. Time excludes shared preparation. Warm cache/order effects possible.",
        "source_sha256": {
            p: sha256((ROOT / p).read_bytes()).hexdigest()
            for p in ["stealer_agent/investigation.py", "eval/compare_link_search.py"]
        },
        "results": outputs,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "--output", type=Path, default=ROOT / "evidence/local/web-link-comparison.json"
    )
    args = p.parse_args()
    dump_json(args.output, experiment())
