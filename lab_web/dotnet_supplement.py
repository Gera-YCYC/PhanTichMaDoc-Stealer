"""Optional .NET source search and report bound to a completed local case."""

import json
from copy import deepcopy
from hashlib import sha256
from time import perf_counter
from uuid import uuid4

from eval.dotnet_followup import PROMPT, fixed_queries, initial, menu
from lab_web.cases import (
    absorb,
    cited_windows,
    directory,
    display_claim,
    trusted_report,
)
from scripts.replay_card_report import reconstruct
from stealer_agent.evidence_cards import create_card_report
from stealer_agent.followup_report import followup_cards
from stealer_agent.journal import Journal, record_model_request, verify_journal
from stealer_agent.model_projection import ModelEvidenceView
from stealer_agent.redaction import redact_document
from stealer_agent.security import guard_observation
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient, ToolClient


def summarize(checked, evidence):
    claims = []
    for claim, kept in [(c, True) for c in checked["claims"]] + [
        (r["claim"], False) for r in checked["rejected_claims"]
    ]:
        shown = display_claim(claim, evidence, rejected=True)
        shown["text"] = redact_document(
            claim["text"], context=(r["quote"] for r in claim["evidence"])
        )[0]
        claims.append({**shown, "kept": kept})
    return {
        "claims": claims,
        "windows": cited_windows(evidence, {"nodes": [], "edges": []}, claims),
    }


def latest(folder, run, digest, model):
    for path in sorted(
        folder.glob("supplements/extra_*/events.jsonl"),
        key=lambda p: p.stat().st_mtime_ns,
        reverse=True,
    ):
        content = path.read_bytes()
        if not content.endswith(b"\n"):
            continue
        lines = content.splitlines()
        end = json.loads(lines[-1])
        if end["event"] != "supplement_finished":
            continue
        verify_journal(path)
        start = json.loads(lines[0])
        if (
            start["event"] != "start"
            or (start["run"], start["sample_sha256"], start["model"])
            != (run, digest, model)
            or start["parent_sha256"]
            != sha256((folder / "events.jsonl").read_bytes()).hexdigest()
            or end["display"]["id"] != path.parent.name
        ):
            raise ValueError("Phụ lục khác hồ sơ được chọn.")
        return end["display"]
    return None


def generate(run, cfg, key):
    folder = directory(run)
    report = trusted_report(run)
    base, used, _ = initial(report["sample"], run)
    original = next(iter(base.values()))
    model = OllamaClient({**cfg, "model": report["model"]["tag"]})
    vm = ToolClient(cfg, key)
    if model.inspect()["digest"] != report["model"]["digest"]:
        raise ValueError("Digest model khác với lần lập hồ sơ.")
    vm.inspect()
    sample = report["sample"]
    fresh = vm.call("decompile_dotnet", {"sample": sample})
    for field, expected in {
        "status": "ok",
        "tool": "decompile_dotnet",
        "sample": sample,
        "sample_sha256": report["sample_sha256"],
        "output_sha256": original["output_sha256"],
    }.items():
        if fresh.get(field) != expected:
            raise ValueError("Kết quả dịch ngược mới khác nguồn trong hồ sơ.")
    journal = Journal(folder / "supplements" / ("extra_" + uuid4().hex[:12]))
    journal.append(
        "start",
        run=run,
        parent_sha256=sha256((folder / "events.jsonl").read_bytes()).hexdigest(),
        sample_sha256=fresh["sample_sha256"],
        output_sha256=fresh["output_sha256"],
        fresh_eid=fresh["evidence_id"],
        model=report["model"]["digest"],
    )
    calls = 0
    started = perf_counter()

    def invoke(messages, schema, phase, evidence):
        nonlocal calls
        free = available_memory_bytes()
        if free is not None and free < 256 * 1024 * 1024:
            raise RuntimeError("Thiếu RAM để tiếp tục đọc chứng cứ.")
        calls += 1
        record_model_request(
            journal,
            step=calls,
            phase=phase,
            messages=messages,
            schema=schema,
            evidence=evidence,
        )
        response, usage = model.chat(messages, schema)
        journal.append(
            "model_response", step=calls, phase=phase, response=response, metrics=usage
        )
        return response

    try:
        prior = deepcopy(base)
        view = ModelEvidenceView()
        fixed = fixed_queries(used)[:2]
        observations, steps = [], []
        for index in range(4):
            if index < len(fixed):
                query = fixed[index]
                mode = "fixed"
            else:
                choices = menu(prior, used)
                if not choices:
                    break
                schema = {
                    "type": "object",
                    "properties": {"choice": {"enum": list(choices)}},
                    "required": ["choice"],
                    "additionalProperties": False,
                }
                inputs = {"candidates": choices, "previous_searches": sorted(used)}
                reply = invoke(
                    [
                        {"role": "system", "content": PROMPT},
                        {"role": "user", "content": json.dumps(inputs)},
                    ],
                    schema,
                    "choose_query",
                    [],
                )
                query = reply.get("choice")
                if query not in choices:
                    raise ValueError("Truy vấn nằm ngoài danh sách cho phép.")
                mode = "adaptive"
            used.add(query.casefold())
            raw = vm.call(
                "search_evidence",
                {"sample": sample, "evidence_id": fresh["evidence_id"], "query": query},
            )
            if (
                raw.get("status") != "ok"
                or raw.get("search_query") != query
                or any(
                    raw[k] != fresh[k]
                    for k in (
                        "sample",
                        "sample_sha256",
                        "tool",
                        "output_sha256",
                        "evidence_id",
                    )
                )
            ):
                raise ValueError("Truy vấn trả về sai nguồn.")
            obs = view.observation(guard_observation(raw)[0])
            absorb(prior, obs)
            view.refresh(prior)
            journal.append("search", mode=mode, observation=obs)
            observations.append(obs)
            steps.append(
                {"mode": mode, "hits": obs["hit_count"], "rows": len(obs["lines"])}
            )
        evidence = reconstruct(
            [{"event": "observation", "model_visible": o} for o in observations]
        )
        cards = (
            followup_cards(evidence, observations, original["line_map"])
            if evidence
            else []
        )
        checked = {"claims": [], "rejected_claims": []}
        if cards:
            _, checked = create_card_report(
                evidence,
                fresh["sample_sha256"],
                invoke,
                journal,
                max_cards=4,
                card_selector=lambda *args, **kwargs: cards,
            )
        display = {
            **summarize(checked, evidence),
            "steps": steps,
            "id": journal.directory.name,
            "cards": len(cards),
            "model_calls": calls,
            "seconds": round(perf_counter() - started, 3),
        }
        journal.append("supplement_finished", checked=checked, display=display)
        verify_journal(journal.path)
        return display
    except Exception as exc:
        journal.append("supplement_failed", error=type(exc).__name__)
        raise
