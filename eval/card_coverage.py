"""Compare report-card selection using the actual observations of the web benchmark.

The candidate sees observed source, parser facts and search hits only. Reference
units enter after selection. This measures row availability, not report accuracy.
"""

from copy import deepcopy
from hashlib import sha256
import argparse
import json
from pathlib import Path

from eval.web_report_exposure import events, source_id
from eval.web_report_quality import EVIDENCE, PROFILE, ROOT, dotnet_profiles, read
from scripts.replay_card_report import reconstruct
from stealer_agent.context_cards import linked_cards
from stealer_agent.evidence_cards import CODE_TOOLS, imports_only, select_cards
from stealer_agent.operation_context import BLOCKED, enrich_card
from stealer_agent.journal import dump_json


def refs(card):
    return card.get("references", [card["reference"]])


def positions(card):
    return {
        (r["evidence_id"], n)
        for r in refs(card)
        for n in range(r["line"], r["end_line"] + 1)
    }


def code_size(card):
    # Match the numbered source sections in create_card_report, including headers.
    sections = []
    for i, ref in enumerate(refs(card), 1):
        numbered = "\n".join(
            f"{n} | {s}" for n, s in enumerate(ref["quote"].split("\n"), ref["line"])
        )
        sections.append(
            f"SECTION {i} original lines {ref['line']}-{ref['end_line']}\n{numbered}"
        )
    return len("\n\n".join(sections).encode())


def active(card):
    return not all(imports_only(r["quote"]) for r in refs(card))


def candidates(records, original):
    yield from original
    decoded = any(r["tool"] == "decode_python_literals" for r in records.values())
    for eid, record in records.items():
        tool = record["tool"]
        if record["status"] != "ok" or tool not in CODE_TOOLS:
            continue
        if decoded and tool in {"disassemble_python", "decompile_python"}:
            continue
        line_map = record["line_map"]
        anchors = {g[0] for g in record.get("focus_groups", []) if g}
        # Cover each contiguous island of already retrieved source. A global
        # stride across disconnected hits can miss a small island altogether.
        for n in sorted(line_map):
            if n - 1 not in line_map:
                start = n
            if (n - start) % 16 == 0:
                anchors.add(n)
        for anchor in sorted(anchors):
            single = {eid: {**record, "context_links": [], "focus_groups": [[anchor]]}}
            selections = select_cards(single, max_cards=1)
            if selections and anchor in selections[0]["focus_lines"]:
                yield selections[0]
        for link in record.get("context_links", []):
            single = {eid: {**record, "context_links": [link]}}
            for card in linked_cards(single, max_cards=1, max_chars=4600):
                yield enrich_card(card, single)


def select(records, original, *, supplements=0):
    """One replacement per active slot, within its original numbered-source bytes."""
    groups = {
        (eid, g[0])
        for eid, r in records.items()
        for g in r.get("focus_groups", [])
        if g
    }
    pool = {}
    for card in candidates(records, original):
        key = tuple((r["evidence_id"], r["line"], r["end_line"]) for r in refs(card))
        if (
            key in pool
            or not active(card)
            or any(marker in r["quote"] for r in refs(card) for marker in BLOCKED)
        ):
            continue
        covered = positions(card)
        kinds = {f["operation"] for f in card.get("operations", [])}
        pool[key] = (card, code_size(card), covered, covered & groups, kinds)
    picked = []
    used_rows = set().union(*(positions(c) for c in original)) if supplements else set()
    used_kinds = (
        {f["operation"] for c in original for f in c.get("operations", [])}
        if supplements
        else set()
    )
    limits = [code_size(c) for c in original]
    if supplements:
        limits = [max(limits, default=0)] * supplements
    for limit in limits:
        eligible = [
            item for item in pool.values() if item[1] <= limit and item[2] - used_rows
        ]
        if not eligible:
            continue
        card, _, rows, _, kinds = max(
            eligible,
            key=lambda item: (
                len(item[4] - used_kinds),
                len(item[3] - used_rows),
                len(item[2] - used_rows),
                -item[1],
            ),
        )
        used_rows.update(rows)
        used_kinds.update(kinds)
        picked.append({**card, "card_id": f"K{len(picked) + 1}"})
    return picked


def extend(records, original):
    """Retain the original ranges and add contiguous guarded rows under a 20% allowance."""
    cards = deepcopy(original)
    seen = set().union(*(positions(c) for c in original))
    for card in cards:
        limit = code_size(card) * 120 // 100
        covered = positions(card)
        while True:
            choices = []
            for i, ref in enumerate(refs(card)):
                # Single-line import or binding references remain exact.
                if not 2 <= ref["end_line"] - ref["line"] < 39:
                    continue
                eid = ref["evidence_id"]
                record = records[eid]
                for side, n in (
                    ("line", ref["line"] - 1),
                    ("end_line", ref["end_line"] + 1),
                ):
                    text = record["line_map"].get(n)
                    if (
                        text is None
                        or (eid, n) in covered
                        or any(m in text for m in BLOCKED)
                    ):
                        continue
                    if record["tool"] == "decode_python_literals" and (
                        (record["line_metadata"][n].get("source_line") or 0) <= 2
                        or text.startswith(
                            ("# STATIC DECODE PROVENANCE ", "# CANDIDATE ")
                        )
                    ):
                        continue
                    before = side == "line"
                    updated = {
                        **ref,
                        side: n,
                        "quote": text + "\n" + ref["quote"]
                        if before
                        else ref["quote"] + "\n" + text,
                    }
                    possible = refs(card).copy()
                    possible[i] = updated
                    if (
                        sum(len(r["quote"]) for r in possible) > 4600
                        or code_size({"reference": possible[0], "references": possible})
                        > limit
                    ):
                        continue
                    choices.append(
                        ((eid, n) not in seen, -len(text), -i, before, i, updated, n)
                    )
            if not choices:
                break
            _, _, _, _, index, updated, n = max(choices, key=lambda c: c[:4])
            card["references"][index] = updated
            card["reference"] = card["references"][0]
            covered.add((updated["evidence_id"], n))
            seen.add((updated["evidence_id"], n))
    return cards


def evaluate():
    batch = read(EVIDENCE / "web-current-batch.json")
    profiles = {
        PROFILE: next(
            r["run_id"] for r in batch["runs"] if r["sample"] == "public_python2024.bin"
        )
    }
    profiles.update({p: run for run, p in dotnet_profiles().values()})
    results = []
    for profile_path, run in profiles.items():
        journal = events(run)
        records = reconstruct(journal)
        original = next(
            e["cards"] for e in journal if e["event"] == "evidence_cards_selected"
        )
        if select_cards(records) != original:
            raise ValueError("Historical cards differ from replay: " + run)
        baseline = [c for c in original if active(c)]
        requests = [
            json.loads(e["messages"][-1]["content"])
            for e in journal
            if e["event"] == "model_request" and e["phase"] == "card_generate"
        ]
        if [(r["card_id"], len(r["code"].encode())) for r in requests] != [
            (c["card_id"], code_size(c)) for c in baseline
        ]:
            raise ValueError("Numbered source or request budget differs")
        candidate = select(records, baseline)
        extended = extend(records, baseline)
        supplement = select(records, baseline, supplements=2)

        profile = read(profile_path)
        digest = profile["sample_sha256"]
        final = read(EVIDENCE / f"web-{run}.json")
        if (
            final["sha256"] != digest
            or final["journal_sha256"]
            != sha256((ROOT / "runs" / run / "events.jsonl").read_bytes()).hexdigest()
        ):
            raise ValueError("Source identity differs")
        eid = source_id(profile, journal)
        arms = {}
        for name, cards in (
            ("baseline", baseline),
            ("candidate", candidate),
            ("extended", extended),
            ("two_extra", baseline + supplement),
        ):
            windows = [positions(c) for c in cards]
            hits = []
            for u in profile["units"]:
                needed = {
                    (eid, n)
                    for ref in u["source_references"]
                    for n in range(ref["line"], ref["end_line"] + 1)
                }
                if any(needed <= w for w in windows):
                    hits.append(u["id"])
            arms[name] = {
                "cards": len(cards),
                "numbered_source_bytes": sum(map(code_size, cards)),
                "in_one_card": hits,
                "coverage": len(hits) / len(profile["units"]),
                "card_ranges": [
                    [[r["evidence_id"], r["line"], r["end_line"]] for r in refs(c)]
                    for c in cards
                ],
            }
        a, b, c = [
            set(arms[n]["in_one_card"]) for n in ("baseline", "candidate", "extended")
        ]
        results.append(
            {
                "run": run,
                "sample": final["sample"],
                "journal_sha256": final["journal_sha256"],
                "profile_sha256": sha256(profile_path.read_bytes()).hexdigest(),
                "units": len(profile["units"]),
                **arms,
                "gained": sorted(b - a),
                "lost": sorted(a - b),
                "extended_gained": sorted(c - a),
                "extended_lost": sorted(a - c),
                "extra_gained": sorted(set(arms["two_extra"]["in_one_card"]) - a),
            }
        )
    return {
        "scope": "Rows available together in a generation card on development samples. Novelty arm uses the original per-slot numbered-source byte budget. Extension arm retains original rows with up to 20% more numbered-source bytes per slot. The separate supplement arm adds at most two generation slots per sample. Token use and report quality require actual inference.",
        "results": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate()
    if args.output:
        dump_json(args.output, result)
    elif result != read(EVIDENCE / "web-card-coverage.json"):
        raise ValueError("Different published experiment")
    for row in result["results"]:
        print(
            row["sample"],
            [
                (
                    row[n]["cards"],
                    row[n]["numbered_source_bytes"],
                    len(row[n]["in_one_card"]),
                )
                for n in ("baseline", "candidate", "extended", "two_extra")
            ],
            "gained",
            len(row["gained"]),
            "lost",
            len(row["lost"]),
        )
