"""Report on further static searches without counting an old window twice."""

from .evidence_cards import imports_only, select_cards
from .operation_context import BLOCKED


def followup_cards(evidence, queries, original_rows, limit=4):
    """Give each successful search a turn before spending its second hit."""
    if len(evidence) != 1 or not 1 <= limit <= 12:
        raise ValueError("Expected a single decompiler output and bounded budget")
    eid, record = next(iter(evidence.items()))
    pools = []
    for obs in queries:
        if (
            obs["evidence_id"] != eid
            or obs["output_sha256"] != record["output_sha256"]
            or obs["sample_sha256"] != record["sample_sha256"]
            or obs["tool"] != "decompile_dotnet"
            or obs["status"] != "ok"
        ):
            raise ValueError("Follow-up search belongs to a different source")
        candidates = []
        for group in obs["search_groups"]:
            anchor = group["anchor_line"]
            if anchor not in group["lines"] or anchor not in record["line_map"]:
                continue
            focus = {**record, "focus_groups": [[anchor]], "context_links": []}
            for card in select_cards({eid: focus}, max_cards=1):
                ref = card["reference"]
                if (
                    anchor in card["focus_lines"]
                    and ref["line"] <= anchor <= ref["end_line"]
                    and not imports_only(ref["quote"])
                    and not any(m in ref["quote"] for m in BLOCKED)
                ):
                    candidates.append(card)
        pools.append(candidates)
    used = set(original_rows)
    selected = []
    while len(selected) < limit:
        size = len(selected)
        for pool in pools:

            def fresh(card):
                ref = card["reference"]
                return set(range(ref["line"], ref["end_line"] + 1)) - used

            if not pool:
                continue
            card = max(pool, key=lambda c: len(fresh(c)))
            novel = fresh(card)
            pool.remove(card)
            if novel:
                selected.append({**card, "card_id": "K" + str(len(selected) + 1)})
                used.update(novel)
            if len(selected) == limit:
                break
        if len(selected) == size:
            break
    return selected
