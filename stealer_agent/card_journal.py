"""Recover the exact request for each rejected behavior from a verified journal."""

import json


def rejected_card_requests(events):
    proposed = {}
    pending = None
    for event in events:
        if event["event"] == "card_claim_proposed":
            claim = event["claim"]
            proposed[claim["id"]] = claim
        elif event["event"] == "model_request" and event["phase"] == "card_review":
            pending = event
        elif event["event"] == "card_claim_review":
            claim = proposed[event["claim_id"]]
            check = event["check"]
            if (
                pending is None
                or json.loads(pending["messages"][-1]["content"])["claim"]
                != claim["text"]
            ):
                raise ValueError("Mismatched claim and review")
            if claim["kind"] == "behavior" and not check["supported"]:
                yield claim, check, pending
            pending = None
