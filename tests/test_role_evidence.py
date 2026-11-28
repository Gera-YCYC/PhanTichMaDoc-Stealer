from hashlib import sha256

import pytest
from jsonschema.exceptions import ValidationError

from stealer_agent.journal import canonical
from stealer_agent.role_evidence import COLLECT, LINK, SEND, review_pair


def source():
    rec = {"sample_sha256": "b"*64, "evidence_id": "ev1", "output_sha256": "c"*64,
           "tool":"decompile_python", "status":"ok", "line_map":{7:"note = 'example'", 8:"mailer.sendmail(a, b, note)"}}
    fact = {**{k:rec[k] for k in ("sample_sha256","output_sha256","evidence_id")},
            "operation":"smtp_send","backend":"static-operation-facts/6","ranges":[{"line":8,"end_line":8}]}
    rec["operation_facts"] = [{**fact, "fact_id":"op_" + sha256(canonical(fact)).hexdigest()[:16]}]
    claim = {"kind":"behavior","id":"C1","text":"The SMTP client sends the note.",
             "evidence":[{"evidence_id":"ev1", "line":7, "end_line":8,"quote":"\n".join(rec["line_map"].values())}]}
    return claim, {"ev1":rec}


def decide(answer):
    return lambda *args: answer


@pytest.mark.parametrize("damage", ["different_sample", "different_quote", "missing_row", "changed_fact", "outside_citation"])
def test_send_requires_original_bound_source(damage):
    claim, records = source()
    rec = records["ev1"]
    if damage == "different_sample":
        rec["sample_sha256"] = "d"*64
    if damage == "different_quote":
        claim["evidence"][0]["quote"] += "!"
    if damage == "missing_row":
        del rec["line_map"][7]
    if damage == "changed_fact":
        rec["operation_facts"][0]["ranges"][0]["line"] = 7
    if damage == "outside_citation":
        claim["evidence"][0].update(end_line=7,quote=rec["line_map"][7])
    def unexpected(*_):
        pytest.fail("Unbound evidence reached the model")
    assert review_pair(claim, SEND, records, "b"*64, unexpected)["status"] in {"no_bound_send","unverified_citation"}


def test_only_a_matching_send_row_is_selectable_and_review_can_abstain():
    claim, records = source()
    for supports in (True, False):
        result = review_pair(claim, SEND, records, "b"*64, decide({"send":"L2","supports":supports}))
        assert (result["status"] == "supported_by_review") == supports
        assert result["witnesses"][0]["line"] == 8
        assert result["witnesses"][0]["fact"] == records["ev1"]["operation_facts"][0]["fact_id"]
    with pytest.raises(ValidationError):
        review_pair(claim, SEND, records, "b"*64, decide({"send":"L1","supports":True}))


@pytest.mark.parametrize(("role","parts"), [(COLLECT,{"read":"L1","sensitive_source":"none"}),
                                           (LINK,{"send":"L2","sensitive_source":"L1","binding_to_payload":"none"})])
def test_a_missing_part_leaves_a_proposed_role_unresolved(role, parts):
    claim, records = source()
    assert review_pair(claim, role, records, "b"*64, decide({**parts,"supports":True}))["status"] == "insufficient"
