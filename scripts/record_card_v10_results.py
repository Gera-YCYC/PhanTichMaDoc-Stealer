"""Pinned source audit of v10 reporting on actual v9 VM evidence; not a demo run."""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.record_card_v9_results import RUN as SOURCE_RUN, NOTES as V9_NOTES
from scripts.replay_card_report import reconstruct
from stealer_agent.journal import canonical, dump_json, verify_journal
from eval.atomic_units import calculate as atomic_score
from eval.claim_audit import calculate as claim_score

RUN = '20261127T232149_05950420'
RAW_SHA = '9e0164dc1e998979de887f9d7e5e5aed699cf40e2d187a4466758b07d6ad8f45'
NOTES = {
    'C1': V9_NOTES['C1'][1], 'C2': V9_NOTES['C2'][1], 'C3': V9_NOTES['C3'][1],
    'C4': V9_NOTES['C4'][1],
    'C5': 'The complete helper copies Login Data into the temporary path then opens it with sqlite3.connect. No query result or runtime success is inferred.',
    'C6': 'Both open/read operations on the Local State path are supplied; the prose uses the source path expression and does not invent a concrete IO class.',
    'C7': 'The complete helper selects encrypted_key from parsed Local State, Base64-decodes it, removes the prefix, calls imported CryptUnprotectData and selects the unprotected data. Source supports the static key-decryption operation despite same-model rejection.',
    'C8': V9_NOTES['C10'][1], 'C9': V9_NOTES['C11'][1], 'C10': V9_NOTES['C13'][1],
    'C11': 'The credit-card helper includes sqlite3.connect, conn.cursor and the SELECT from credit_cards. This describes connection/query only, not decryption or actual rows.',
    'C12': V9_NOTES['C16'][1],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    directory = ROOT / 'private/report-experiments' / RUN
    source = ROOT / 'runs' / SOURCE_RUN
    verify_journal(directory / 'events.jsonl')
    verify_journal(source / 'events.jsonl')
    journal_bytes = (directory / 'events.jsonl').read_bytes()
    events = [json.loads(s) for s in journal_bytes.splitlines()]
    source_bytes = (source / 'events.jsonl').read_bytes()
    source_events = [json.loads(s) for s in source_bytes.splitlines()]
    assert events[0]['source_journal_sha256'] == sha(source_bytes)
    assert events[-1]['event'] == 'replay_finished'
    raw_bytes = (directory / 'report.model-raw.json').read_bytes()
    checked_bytes = (directory / 'report.checked.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA
    raw, checked = json.loads(raw_bytes), json.loads(checked_bytes)
    evidence = reconstruct(source_events)
    digest = json.loads((source / 'report.private.json').read_bytes())['sample_sha256']
    assert set(NOTES) == {c['id'] for c in raw['claims']}
    rows = []
    for claim in raw['claims']:
        refs = []
        for ref in claim['evidence']:
            record = evidence[ref['evidence_id']]
            assert record['sample_sha256'] == digest
            quote = '\n'.join(record['line_map'][n] for n in range(ref['line'], ref['end_line'] + 1))
            assert quote == ref['quote']
            refs.append({k: ref[k] for k in ('evidence_id', 'line', 'end_line')} |
                        {'projected_quote_sha256': sha(quote.encode())})
        rows.append({'claim_id': claim['id'], 'label': 'correct', 'grounded': True,
                     'reviewer': 'automated source audit, not Qwen self-review or human approval',
                     'truth_reference': refs, 'reason': NOTES[claim['id']]})
    audit = {'run_id': RUN, 'sample_sha256': digest, 'raw_report_sha256': RAW_SHA,
             'journal_sha256': sha(journal_bytes), 'source_run': SOURCE_RUN,
             'dataset_origin': 'public-development-sample; captured-feature reporting experiment',
             'human_reviewers': [], 'claims': rows,
             'scope': 'All raw claims including rejected ones; static behavior only. Not end-to-end validation.'}
    out = ROOT / 'deliverables/real-demo-evidence'
    dump_json(ROOT / 'eval/adjudications/python2024-cards-v10-report-stage-audit.json', audit)
    score = claim_score(raw_bytes, checked, audit)
    dump_json(out / 'python2024-cards-v10-report-stage-claim-score.json', score)
    profile_bytes = (ROOT / 'eval/reference_units/python2024.atomic-v2.json').read_bytes()
    assignments = {'C1': [('A18', None)],
                   'C2': [('A25', ' with the zipped'), ('A26', ' including authentication'), ('A24', None)],
                   'C3': [('A27', None)], 'C4': [('A05', None)], 'C5': [('A06', None)],
                   'C6': [('A01', None)], 'C7': [('A03', None)], 'C8': [('A15', None)],
                   'C9': [('A30', None)], 'C10': [('A10', None)],
                   'C11': [('A11', ' and executes'), ('A12', None)], 'C12': [('A31', None)]}
    mapping = {'schema_version': 1, 'sample_sha256': digest, 'profile_sha256': sha(profile_bytes),
               'raw_report_sha256': RAW_SHA, 'checked_report_sha256': sha(checked_bytes),
               'reviewer': 'automated source audit; no human or lecturer approval',
               'method': 'Exhaustive explicit spans, same atomic-v2 reference as v9, all rejected claims retained.', 'claims': []}
    references = {r['claim_id']: r['truth_reference'] for r in rows}
    for claim in raw['claims']:
        cid, text, cursor, atoms = claim['id'], claim['text'], 0, []
        for unit, next_start in assignments[cid]:
            end = text.index(next_start, cursor) if next_start else len(text)
            atoms.append({'start': cursor, 'end': end, 'label': 'correct', 'unit_key': 'PY24-' + unit,
                          'reference_id': 'PY24-' + unit, 'reason': NOTES[cid], 'source_references': references[cid]})
            cursor = end
        mapping['claims'].append({'claim_id': cid, 'atoms': atoms})
    dump_json(ROOT / 'eval/adjudications/python2024-cards-v10-report-stage-atomic-mapping.json', mapping)
    atomic = atomic_score(profile_bytes, raw_bytes, checked_bytes, mapping)
    dump_json(out / 'python2024-cards-v10-report-stage-atomic-score.json', atomic)
    def cards_hash(items):
        cards = next(e['cards'] for e in items if e['event'] == 'evidence_cards_selected')
        return sha(canonical([c.get('references', [c['reference']]) for c in cards]))
    assert cards_hash(events) == cards_hash(source_events)
    start = events[0]
    receipt = {'run_id': RUN, 'source_run': SOURCE_RUN,
               'kind': 'real-slm-on-captured-vm-features-not-end-to-end-demo',
               'sample_sha256': digest, 'source_journal_sha256': sha(source_bytes),
               'report_method': checked['report_method'], 'source_manifest_sha256': start['source_manifest_sha256'],
               'source_files': start['source_files'], 'reporter_source_sha256': start['reporter_source_sha256'],
               'model': {k: start['model'][k] for k in ('tag', 'digest', 'size_bytes', 'details')},
               'journal_sha256': sha(journal_bytes), 'journal_chain_verified': True,
               'raw_report_sha256': RAW_SHA, 'checked_report_sha256': sha(checked_bytes),
               'raw_claim_count': len(raw['claims']), 'accepted_claim_count': len(checked['claims']),
               'rejected_claim_count': len(checked['rejected_claims']),
               'raw_claims_by_kind': dict(Counter(c['kind'] for c in raw['claims'])),
               'metrics': events[-1]['metrics'], 'verdict': checked['verdict'],
               'same_source_card_ranges_and_quotes_as_v9': True, 'source_card_references_sha256': cards_hash(events),
               'course_quality_gate_passed': False,
               'limits': ['One development report experiment, not a fresh VM run or a full-corpus grade.',
                          'Changed vocabulary constraint plus API descriptors; not a single-factor causal experiment.',
                          'All 12 narrow claims source-supported, but only 15 of 34 declared units covered; no ATT&CK.',
                          'Same-model review wrongly removes attachment/SMTP and DPAPI claims; verdict remains suspicious.',
                          'Raw excerpts/private credentials not exported; labels are not human or lecturer approval.']}
    dump_json(out / 'python2024-cards-v10-report-stage-run.json', receipt)
    print(json.dumps({'claim_raw': score['raw'], 'atomic_raw': atomic['raw'], 'atomic_after_filter': atomic['after_filter']}))


if __name__ == '__main__':
    main()
