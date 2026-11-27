"""Score a complete source audit of raw claims, retaining rejected candidates.

Adjudications must be supplied from source inspection, never from self-review.
This narrow audit does not estimate recall against a composite reference profile.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def calculate(raw_bytes, checked, audit):
    if hashlib.sha256(raw_bytes).hexdigest() != audit['raw_report_sha256']:
        raise ValueError('Adjudication does not match the exact raw report')
    raw = json.loads(raw_bytes)
    raw_ids = [c['id'] for c in raw['claims']]
    rows = audit['claims']
    row_ids = [c['claim_id'] for c in rows]
    if len(set(raw_ids)) != len(raw_ids) or len(set(row_ids)) != len(row_ids):
        raise ValueError('Duplicate claim IDs')
    if set(row_ids) != set(raw_ids):
        raise ValueError('Audit must cover every raw claim, including rejected claims')
    accepted_ids = {c['id'] for c in checked['claims']}
    rejected_ids = {r['claim']['id'] for r in checked['rejected_claims']}
    if accepted_ids & rejected_ids or accepted_ids | rejected_ids != set(raw_ids):
        raise ValueError('Checked report does not partition raw candidates')
    originals = {c['id']: c for c in raw['claims']}
    for claim in checked['claims'] + [r['claim'] for r in checked['rejected_claims']]:
        if claim != originals[claim['id']]:
            raise ValueError('Checked report changed a raw candidate')
    for row in rows:
        if row['label'] not in {'correct', 'incorrect', 'unsupported'}:
            raise ValueError('Raw claims require a lecturer prediction label')
        if not row.get('reviewer') or not row.get('truth_reference') or not row.get('reason'):
            raise ValueError('Source audit provenance is required')
        if row.get('grounded') is not (row['label'] == 'correct'):
            raise ValueError('Grounding must agree with the source-supported label')

    def score(subset):
        counts = Counter(r['label'] for r in subset)
        total = len(subset)
        return {'claim_count': total, 'counts': {k: counts[k] for k in ('correct', 'incorrect', 'unsupported')},
                'precision': counts['correct'] / total if total else None,
                'hallucination_rate': counts['unsupported'] / total if total else None,
                'grounding_rate': sum(r['grounded'] for r in subset) / total if total else None,
                'recall': None, 'f1': None}

    matrix = Counter(('accepted' if r['claim_id'] in accepted_ids else 'rejected') +
                     ('_correct' if r['label'] == 'correct' else '_not_supported') for r in rows)
    return {'run_id': audit['run_id'], 'raw_report_sha256': audit['raw_report_sha256'],
            'dataset_origin': audit['dataset_origin'], 'sample_sha256': audit['sample_sha256'],
            'raw': score(rows), 'after_filter': score([r for r in rows if r['claim_id'] in accepted_ids]),
            'review_filter': {k: matrix[k] for k in ('accepted_correct', 'accepted_not_supported',
                                                   'rejected_correct', 'rejected_not_supported')},
            'proposed_verdict': raw['verdict'], 'checked_verdict': checked['verdict'],
            'quality_gate_passed': False,
            'limits': ['Complete prediction audit for one development run, not a full-corpus evaluation.',
                       'No human or lecturer approval is asserted; source-audit labels may need correction.',
                       'Recall/F1 remain null until independently declared reference units are fully adjudicated.',
                       'Raw/rejected candidates remain in the primary denominator; filtered scores are secondary.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('adjudications', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    final = args.directory / 'report.private.json'
    checked = json.loads(final.read_text(encoding='utf-8'))['analysis'] if final.is_file() else json.loads(
        (args.directory / 'report.checked.json').read_text(encoding='utf-8'))
    result = calculate((args.directory / 'report.model-raw.json').read_bytes(), checked,
                       json.loads(args.adjudications.read_text(encoding='utf-8')))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
