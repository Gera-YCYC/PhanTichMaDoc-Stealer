"""Verify citations, not semantic truth. Keep rejected claims for independent scoring."""
from __future__ import annotations

import copy
from jsonschema import Draft202012Validator

from .contracts import ATTACK, REPORT_SCHEMA


def validate_report(raw: dict, evidence: dict, sample_sha256: str) -> dict:
    Draft202012Validator(REPORT_SCHEMA).validate(raw)
    accepted, rejected, seen = [], [], set()
    for claim in raw["claims"]:
        errors = []
        if claim["id"] in seen:
            errors.append("duplicate_claim_id")
        seen.add(claim["id"])
        for ref in claim["evidence"]:
            source = evidence.get(ref["evidence_id"])
            if not source or source.get("status") != "ok" or source.get("sample_sha256") != sample_sha256:
                errors.append("unknown_failed_or_wrong_sample_evidence")
                continue
            line_map = source.get('line_map', {})
            if 'end_line' in ref:
                end = ref['end_line']
                if end < ref['line'] or end - ref['line'] >= 40:
                    errors.append('invalid_evidence_range')
                    continue
                numbers = range(ref['line'], end + 1)
                if any(n not in line_map for n in numbers):
                    errors.append('evidence_range_has_missing_lines')
                    continue
                line = '\n'.join(line_map[n] for n in numbers)
                matches = ref['quote'] == line
            else:
                line = line_map.get(ref['line'], '')
                matches = len(ref['quote']) <= 600 and ref['quote'] in line
            if "[REDACTED-INJECTION]" in line or not matches:
                errors.append("quote_not_found_at_cited_line")
        if claim["kind"] == "ioc":
            if not claim["value"] or not any(claim["value"] in e["quote"] for e in claim["evidence"]):
                errors.append("ioc_value_not_in_quote")
        if claim["kind"] == "attack" and claim["technique_id"] not in ATTACK:
            errors.append("unknown_attack_technique")
        if claim['kind'] in ('behavior','attack'):
            code_tools={'decompile_dotnet','decompile_python','disassemble_python','python_ast','decode_python_literals'}
            if not any(evidence.get(ref['evidence_id'],{}).get('tool') in code_tools for ref in claim['evidence']):
                errors.append('behavior_or_attack_requires_code_evidence_not_only_strings_or_ioc')
        if claim['kind']!='ioc' and claim['value']:
            errors.append('value_is_reserved_for_literal_ioc')
        if claim['kind']!='attack' and claim['technique_id']:
            errors.append('technique_id_requires_an_attack_claim')
        if errors:
            rejected.append({"claim": claim, "reasons": sorted(set(errors))})
        else:
            accepted.append(claim)
    accepted_ids = {c["id"] for c in accepted}
    refs = raw["verdict_claim_ids"]
    verdict = raw["verdict"]
    reasons = []
    if verdict != "inconclusive" and (not refs or not set(refs) <= accepted_ids):
        verdict = "inconclusive"
        reasons.append("verdict_has_no_verified_claim_references")
    if rejected:
        # A rejected claim may affect the conclusion; never silently keep it.
        verdict = "inconclusive"
        reasons.append("one_or_more_claims_rejected")
    if verdict != "inconclusive" and not any(c["kind"] == "behavior" for c in accepted):
        verdict = "inconclusive"
        reasons.append("metadata_and_ioc_candidates_do_not_establish_a_verdict")
    result = copy.deepcopy(raw)
    result.update(verdict=verdict, proposed_verdict=raw["verdict"], claims=accepted, rejected_claims=rejected,
                  validation_notes=reasons, requires_semantic_review=True,
                  citation_coverage=(len(accepted) / len(raw["claims"]) if raw["claims"] else None),
                  validation_scope="quote/line/source verification only; not semantic truth or measured hallucination")
    return result
