"""Exact intersection/union agreement for three runs on the same sample/model."""
import argparse
import json
from pathlib import Path


def claim_key(claim):
    kind = claim["kind"]
    if kind == "ioc":
        return kind, claim["value"]
    if kind == "attack":
        return kind, claim["technique_id"]
    return kind, claim["text"].strip()


def calculate(reports):
    if len(reports) != 3:
        raise ValueError("Exactly three reports are required")
    identities = {(r.get("sample_sha256"), r["model"].get("digest")) for r in reports}
    if len(identities) != 1 or not all(next(iter(identities))):
        raise ValueError("Three runs must share a verified sample hash and model digest")
    sets = []
    for report in reports:
        if not report["status"].startswith("completed"):
            raise ValueError("Incomplete runs cannot be used to claim stability")
        sets.append({claim_key(c) for c in report["analysis"]["claims"]})
    common, union = set.intersection(*sets), set.union(*sets)
    return {"stable_claims": len(common), "union_claims": len(union),
            "stability": len(common) / len(union) if union else None,
            "verdict_agreement": len({r["analysis"]["verdict"] for r in reports}) == 1,
            "method": "exact canonical values; wording differences count as unstable; empty set is undefined"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs=3)
    args = parser.parse_args()
    print(json.dumps(calculate([json.loads(Path(p).read_text(encoding="utf-8")) for p in args.reports]), indent=2))
