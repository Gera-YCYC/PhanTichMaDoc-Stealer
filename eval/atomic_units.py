"""Score explicitly adjudicated atomic units with the same P/R/F1 unit of count.

This validates a complete mapping; it never invents semantic labels. A source
audit must split every prediction and declare the reference independently of
model self-review. Duplicates count once, including repeated false assertions.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

LABELS = {'correct', 'incorrect', 'unsupported'}
KINDS = {'behavior', 'ioc', 'attack', 'observation'}


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def calculate(profile_bytes, raw_bytes, checked_bytes, mapping):
    for key, data in [('profile_sha256', profile_bytes), ('raw_report_sha256', raw_bytes),
                      ('checked_report_sha256', checked_bytes)]:
        if mapping.get(key) != fingerprint(data):
            raise ValueError('Fingerprint mismatch: ' + key)
    profile, raw, checked = map(json.loads, (profile_bytes, raw_bytes, checked_bytes))
    if profile.get('schema_version') != 1 or mapping.get('schema_version') != 1:
        raise ValueError('Unknown atomic-unit contract')
    if mapping.get('sample_sha256') != profile.get('sample_sha256') or not profile.get('sample_sha256'):
        raise ValueError('Sample mismatch')
    if not profile.get('scope') or not profile.get('source_references') or not profile.get('reference_method'):
        raise ValueError('Reference scope and independent provenance required')
    if profile.get('model_self_review_used_as_truth') is not False:
        raise ValueError('Model self-review cannot supply reference truth')
    if not mapping.get('reviewer') or not mapping.get('method'):
        raise ValueError('Explicit adjudication provenance required')
    units = {u['id']: u for u in profile['units']}
    if not units or len(units) != len(profile['units']):
        raise ValueError('Reference IDs must be nonempty and unique')
    for unit in units.values():
        if unit.get('kind') not in KINDS or not unit.get('proposition') or not unit.get('source_references'):
            raise ValueError('Every reference requires kind, atomic proposition and source')
    originals = {c['id']: c for c in raw['claims']}
    if len(originals) != len(raw['claims']):
        raise ValueError('Duplicate raw claim IDs')
    kept = {c['id'] for c in checked['claims']}
    all_checked = checked['claims'] + [r['claim'] for r in checked['rejected_claims']]
    if len(all_checked) != len(originals) or {c['id'] for c in all_checked} != set(originals):
        raise ValueError('Checked report must partition every raw candidate exactly once')
    if any(c != originals[c['id']] for c in all_checked):
        raise ValueError('Checked report changed a raw assertion')
    annotations = {r['claim_id']: r for r in mapping['claims']}
    if len(annotations) != len(mapping['claims']) or set(annotations) != set(originals):
        raise ValueError('Map every raw candidate, including rejected assertions')
    rows = []
    for cid, claim in originals.items():
        atoms = annotations[cid]['atoms']
        if not atoms:
            raise ValueError('No silent omission of a raw claim')
        cursor = 0
        for atom in sorted(atoms, key=lambda a: a['start']):
            if set(atom) != {'start', 'end', 'label', 'unit_key', 'reference_id', 'reason', 'source_references'}:
                raise ValueError('Unknown or missing atomic annotation fields')
            start, end = atom['start'], atom['end']
            if type(start) is not int or type(end) is not int or not cursor <= start < end <= len(claim['text']):
                raise ValueError('Invalid or overlapping atomic text spans')
            if claim['text'][cursor:start].strip(' \t\r\n.,;:'):
                raise ValueError('Unadjudicated prediction text')
            cursor = end
            if atom.get('label') not in LABELS or not atom.get('unit_key') or not atom.get('reason') or not atom.get('source_references'):
                raise ValueError('Every atom requires an explicit source judgment')
            rid = atom.get('reference_id')
            if atom['label'] == 'correct':
                if rid not in units or units[rid]['kind'] != claim['kind'] or atom['unit_key'] != rid:
                    raise ValueError('Correct atom must match a declared unit of the same kind; extend an incomplete reference before scoring')
            elif rid is not None or atom['unit_key'] in units:
                raise ValueError('False or unsupported atoms cannot earn reference credit')
            rows.append({**atom, 'claim_id': cid, 'kind': claim['kind'], 'included_after_filter': cid in kept})
        if claim['text'][cursor:].strip(' \t\r\n.,;:'):
            raise ValueError('Unadjudicated trailing prediction text')
    # Stable unit keys mean one proposition has one judgment across duplicate
    # sentences. Contradictory mappings cannot change the denominator silently.
    unique = {}
    for row in rows:
        key = row['unit_key']
        if key in unique and any(row[k] != unique[key][k] for k in ('kind', 'label', 'reference_id')):
            raise ValueError('Conflicting judgments for the same normalized unit')
        unique[key] = row

    def score(items, selected_units):
        candidates = {r['unit_key']: r for r in items}
        counts = Counter(r['label'] for r in candidates.values())
        hits = {r['reference_id'] for r in candidates.values() if r['label'] == 'correct'}
        total, denominator = len(candidates), len(selected_units)
        precision = len(hits) / total if total else None
        recall = len(hits) / denominator if denominator else None
        f1 = (2 * precision * recall / (precision + recall) if precision + recall else 0.0) if precision is not None and recall is not None else None
        return {'prediction_atoms': len(items), 'unique_prediction_units': total,
                'duplicate_atoms': len(items) - total, 'reference_units': denominator,
                'correct': counts['correct'], 'incorrect': counts['incorrect'],
                'unsupported': counts['unsupported'], 'missed': denominator - len(hits),
                'precision': precision, 'recall': recall, 'f1': f1,
                'hallucination_rate': counts['unsupported'] / total if total else None,
                'matched_reference_ids': sorted(hits), 'missed_reference_ids': sorted(set(selected_units) - hits)}

    ready = profile.get('scoring_ready') is True
    scores = {'raw': score(rows, units), 'after_filter': score([r for r in rows if r['included_after_filter']], units)}
    by_kind = {kind: {'raw': score([r for r in rows if r['kind'] == kind],
                                      {uid: u for uid, u in units.items() if u['kind'] == kind}),
                      'after_filter': score([r for r in rows if r['kind'] == kind and r['included_after_filter']],
                                           {uid: u for uid, u in units.items() if u['kind'] == kind})} for kind in sorted(KINDS)}
    if not ready:
        for result in [*scores.values(), *(s for pair in by_kind.values() for s in pair.values())]:
            for metric in ('precision', 'recall', 'f1', 'hallucination_rate'):
                result[metric] = None
    return {'contract': 'source-audited-atomic-units/1', 'profile_id': profile['profile_id'],
            'sample_sha256': profile['sample_sha256'], 'scope': profile['scope'], 'scoring_ready': ready,
            'fingerprints': {k: mapping[k] for k in ('profile_sha256', 'raw_report_sha256', 'checked_report_sha256')},
            **scores, 'by_kind': by_kind, 'mapping_sha256': fingerprint(json.dumps(mapping, sort_keys=True).encode()),
            'human_reviewers': profile.get('human_reviewers', []), 'full_coursework_quality_gate_passed': False,
            'limits': ['Semantic splitting and labels are supplied by a source audit, not inferred by this calculator.',
                       'Scoped reference coverage is not full-corpus recall. Duplicates count once in P and R.',
                       'Every raw candidate, including rejected ones, remains in the primary mapping.',
                       'No approval by a human or lecturer is implied; corpus and verdict gates are separate.']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('profile', 'raw', 'checked', 'mapping', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    result = calculate(a.profile.read_bytes(), a.raw.read_bytes(), a.checked.read_bytes(), json.loads(a.mapping.read_bytes()))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'profile_id': result['profile_id'], 'raw': result['raw'], 'after_filter': result['after_filter']}))


if __name__ == '__main__':
    main()
