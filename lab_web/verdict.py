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
    result = {"proposed": analysis["proposed_verdict"], "final": analysis["verdict"],
              "citations": cited, "roles": roles}
    if "role_checks" in analysis:
        checks = analysis["role_checks"]
        proposed = analysis["proposed_roles"]
        if [(d["role"], d["claim"]) for d in checks] != [(k,i) for k in SUPPORT_KEYS for i in proposed[k]]:
            raise ValueError("Thiếu lần kiểm vai trò đã đề xuất.")
        recovery = analysis.get("send_recovery")
        for key in SUPPORT_KEYS:
            ids = [d["claim"] for d in checks if d["role"] == key and d["status"] == "supported_by_review"]
            if recovery and key == SUPPORT_KEYS[1]:
                sites = recovery["sites"]
                added = [s["claim"] for s in sites if s["status"] == "recovered"]
                if (recovery["outcome"] not in ("already_supported", "searched")
                        or recovery["outcome"] == "already_supported" and (not ids or sites)
                        or set(ids).intersection(added)
                        or list(dict.fromkeys(recovery["prior_citations"] + added)) != cited
                        or len(cited) > 10 or any(c not in valid for c in added)):
                    raise ValueError("Các câu gửi được bổ sung khác với dấu vết kiểm chứng.")
                ids += added
                result["send_recovery"] = recovery
            if ids != analysis["verdict_support"][key]:
                raise ValueError("Kết quả kiểm vai trò khác các câu dùng cho verdict.")
        result["checks"] = checks
    return result
