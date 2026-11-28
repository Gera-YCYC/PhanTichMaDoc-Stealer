"""Display the verdict decision recorded for a case, with its original claim IDs."""
from stealer_agent.verdict_support import SUPPORT_KEYS


def trace(analysis):
    if "verdict_support" not in analysis:
        return None
    behavior = {c["id"] for c in analysis["claims"] if c["kind"] == "behavior"}
    cited = analysis["verdict_claim_ids"]
    valid = behavior.intersection(cited)
    roles = []
    for key in SUPPORT_KEYS:
        ids = analysis["verdict_support"][key]
        unbound = [i for i in ids if i not in valid]
        roles.append({"role": key, "ids": ids, "unbound": unbound,
                      "state": "missing" if not ids else "invalid" if unbound else "cited"})
    for state in ("missing", "invalid"):
        if [r["role"] for r in roles if r["state"] == state] != analysis["verdict_support_" + state]:
            raise ValueError("Trạng thái dẫn chứng khác quyết định đã ghi.")
    return {"proposed": analysis["proposed_verdict"], "final": analysis["verdict"],
            "citations": cited, "roles": roles}
