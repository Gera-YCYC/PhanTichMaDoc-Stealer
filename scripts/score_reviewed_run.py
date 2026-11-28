"""Recompute claim and atomic scores from explicit, hash-pinned source judgments."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.atomic_units import calculate as atomic_score
from eval.claim_audit import calculate as claim_score
from scripts.replay_card_report import reconstruct
from stealer_agent.journal import canonical, dump_json, verify_journal


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def scoped_counts(counts, declared):
    """Keep the original recall denominator while retaining every prediction."""
    hits = set(counts['matched_reference_ids'])
    inside = hits & declared
    wrong = counts['incorrect'] + counts['unsupported']
    precision = len(inside) / (len(inside) + wrong) if inside or wrong else None
    recall = len(inside) / len(declared) if declared else None
    f1 = None
    if precision is not None and recall is not None:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        'reference_units': len(declared), 'correct': len(inside), 'missed': len(declared - inside),
        'supported_outside_scope': sorted(hits - declared), 'incorrect': counts['incorrect'],
        'unsupported': counts['unsupported'], 'prediction_atoms': counts['prediction_atoms'],
        'duplicate_atoms': counts['duplicate_atoms'], 'unique_prediction_units': counts['unique_prediction_units'],
        'all_prediction_precision': counts['precision'], 'all_prediction_hallucination_rate': counts['hallucination_rate'],
        'precision': precision, 'recall': recall, 'f1': f1, 'matched_reference_ids': sorted(inside),
        'missed_reference_ids': sorted(declared - inside),
    }


def score(directory, profile_path, decisions, output):
    journal = directory / 'events.jsonl'
    verify_journal(journal)
    events = [json.loads(line) for line in journal.read_bytes().splitlines()]
    raw_bytes = (directory/'report.model-raw.json').read_bytes()
    profile_bytes = profile_path.read_bytes()
    checked = json.loads((directory/'report.private.json').read_bytes())['analysis']
    if (events[-1]['event'] != 'run_finished' or directory.name != decisions['run_id'] or
            events[-1]['result']['analysis'] != checked or
            fingerprint(raw_bytes) != decisions['raw_report_sha256'] or
            fingerprint(profile_bytes) != decisions['profile_sha256']):
        raise ValueError('Run, profile or review has changed')
    sample = events[-1]['result']['sample_sha256']
    profile = json.loads(profile_bytes)
    if sample != profile['sample_sha256'] or profile.get('scoring_ready') is not True:
        raise ValueError('Reference sample differs')
    rows = decisions['claims']
    claims = json.loads(raw_bytes)['claims']
    if set(rows) != {c['id'] for c in claims}:
        raise ValueError('Every raw claim must have a source judgment')
    source = reconstruct(events)
    audit = {'run_id':directory.name, 'sample_sha256':sample, 'raw_report_sha256':fingerprint(raw_bytes),
             'journal_sha256':fingerprint(journal.read_bytes()), 'claims':[], 'human_reviewers':[],
             'dataset_origin':'public development sample, static analysis in isolated VM'}
    mapping = {'schema_version':1, 'sample_sha256':sample, 'profile_sha256':fingerprint(profile_bytes),
               'raw_report_sha256':fingerprint(raw_bytes), 'checked_report_sha256':fingerprint(canonical(checked)),
               'reviewer':'Source audit of raw and rejected candidates. No lecturer or human approval.',
               'method':'Explicit exhaustive spans. Duplicate operations at the same site count once. API qualifiers are part of the asserted operation.',
               'claims':[]}
    for claim in claims:
        cid = claim['id']
        judgment = rows[cid]
        refs = []
        for ref in claim['evidence']:
            record = source[ref['evidence_id']]
            start, end = ref['line'], ref.get('end_line',ref['line'])
            expected = '\n'.join(record['line_map'][n] for n in range(start,end+1))
            if record['sample_sha256'] != sample or expected != ref['quote']:
                raise ValueError('Submitted citation differs from projection: '+cid)
            refs.append({'evidence_id':ref['evidence_id'],'line':start,'end_line':end,
                         'projected_quote_sha256':fingerprint(expected.encode())})
        text, cursor, atoms = claim['text'], 0, []
        for part in judgment['atoms']:
            end = text.index(part['until'], cursor) if part.get('until') else len(text)
            label = part.get('label', 'correct')
            atoms.append({'start':cursor,'end':end,'label':label,'unit_key':part['key'],
                          'reference_id':part['key'] if label=='correct' else None,
                          'reason':judgment['reason'],'source_references':refs})
            cursor = end
        labels = {a['label'] for a in atoms}
        # A mixed sentence is unsupported if any qualifier lacks source evidence.
        label = 'unsupported' if 'unsupported' in labels else 'incorrect' if 'incorrect' in labels else 'correct'
        audit['claims'].append({'claim_id':cid,'label':label,'grounded':label=='correct',
                                'reviewer':mapping['reviewer'],'truth_reference':refs,'reason':judgment['reason']})
        mapping['claims'].append({'claim_id':cid,'atoms':atoms})
    per_claim = claim_score(raw_bytes,checked,audit)
    # Validate all spans with the common calculator. Additional source-supported
    # propositions are listed separately and never enter the frozen recall denominator.
    extras = decisions.get('additional_findings', [])
    for extra in extras:
        for ref in extra['source_references']:
            record = source[ref['evidence_id']]
            if (record['sample_sha256'] != sample or ref['end_line'] < ref['line'] or
                    any(n not in record['line_map'] for n in range(ref['line'], ref['end_line'] + 1))):
                raise ValueError('Missing source coordinates for additional finding: ' + extra['id'])
    augmented = canonical({**profile, 'units': profile['units'] + extras})
    validation_map = {**mapping, 'profile_sha256': fingerprint(augmented)}
    validated = atomic_score(augmented, raw_bytes, canonical(checked), validation_map)
    stages = ('raw', 'after_filter')
    ids = {u['id'] for u in profile['units']}
    if {f['id'] for f in extras} - set(validated['raw']['matched_reference_ids']):
        raise ValueError('Additional findings must be supported by an explicitly audited prediction')
    atomic = {'contract': 'frozen-reference-plus-separate-source-findings/1',
              'run_id': directory.name, 'profile_id': profile['profile_id'],
              'profile_sha256': fingerprint(profile_bytes), 'raw_report_sha256': fingerprint(raw_bytes),
              'method': 'P and F1 on declared units charge all incorrect or unsupported predictions. Supported extra findings are listed separately. All-prediction precision includes them. Recall uses the frozen denominator.',
              'additional_findings': extras, 'human_reviewers': [],
              'full_coursework_quality_gate_passed': False,
              **{s: scoped_counts(validated[s], ids) for s in stages},
              'by_kind': {kind: {s: scoped_counts(counts[s], {u['id'] for u in profile['units'] if u['kind'] == kind})
                                 for s in stages} for kind, counts in validated['by_kind'].items()}}
    output.mkdir(parents=True,exist_ok=True)
    for name, obj in [('source-audit',audit),('atomic-mapping',mapping),('claim-score',per_claim),('atomic-score',atomic)]:
        dump_json(output/(name+'.json'),obj)
    print(json.dumps({'raw':{k:atomic['raw'][k] for k in ('correct','unsupported','missed','precision','recall','f1')},
                      'after_filter':{k:atomic['after_filter'][k] for k in ('correct','missed','precision','recall','f1')}}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('directory','profile','judgments','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    score(args.directory,args.profile,json.loads(args.judgments.read_bytes()),args.output)
