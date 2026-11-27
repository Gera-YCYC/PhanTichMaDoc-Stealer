"""Export explicit source-audit labels for three pinned reporting experiments.

These labels were established by inspecting source import, binding and call rows;
the model decisions are not the source of truth. Any report change needs a new
audit. Exports contain metadata/coordinates only, never raw excerpts or secrets.
"""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.atomic_units import calculate as atomic_score
from eval.claim_audit import calculate as claim_score
from stealer_agent.journal import canonical, verify_journal

RUNS = {
    '20261127T223237_eb2876a8': 'af09791219dd082f164fbebe588d9d0351195108b8f370965dc59aaf79788cb7',
    '20261127T223332_6006a331': 'dc97559842131eefcfe35383dbc1681b93f4ab8a8444b3e69fffc7c6b4be44bd',
    '20261127T223527_d5fb791e': '127bfe89baf32449b4a189e9cae3d6ee9c60dfc230199890e90bf218aafc6cd3',
}
# Independent source audit assignments, not generated from model include flags.
PYTHON = {
    'op_5841fdfd1dd0fe8a': ('A06', 'SQLite import and connect at row 140 establish a database path expression, not decrypted contents.'),
    'op_eff756d3906f7aac': ('A07', 'Bound cursor execute at row 142 contains the exact login SELECT; no fetch or decryption asserted.'),
    'op_1142bfa57bc5e633': ('A04', 'AES import and GCM construction at row 72 bind decrypt at row 73; input expressions retained.'),
    'op_c87f61e1babf267c': ('A12', 'Connection/cursor rows 164-165 bind the credit_cards SELECT at 166-167; no plaintext claimed.'),
    'op_797d60ee810f241e': ('A18', 'shutil import and make_archive call at row 279 prove argument roles and zip format.'),
    'op_2d2517ecddb76544': ('A25', 'smtplib import, SMTP instance at 106 and sendmail at 109 prove the narrow send call, not attachment contents.'),
}
DOTNET = {
    'op_83eff2ae2facb4df': 3603, 'op_eb3a3d7bf55a506f': 3604,
    'op_43f61026e6f9ee9e': 3577, 'op_1e986d7265952e43': 3578,
    'op_f64022eb9ad5bd17': 3629, 'op_3cca56c66a1a7c16': 3630,
    'op_31d130294317db15': 3681, 'op_35ebe2a651b044f1': 3682,
    'op_bc575cc83560fec2': 3655, 'op_6613e3852c0a83da': 3656,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    profile_path = ROOT / 'eval/reference_units/python2024.atomic-v1.json'
    profile_bytes = profile_path.read_bytes()
    profile = json.loads(profile_bytes)
    receipts = []
    for run_id, expected in RUNS.items():
        directory = ROOT / 'private/report-experiments' / run_id
        verify_journal(directory / 'events.jsonl')
        events_bytes = (directory / 'events.jsonl').read_bytes()
        events = [json.loads(s) for s in events_bytes.splitlines()]
        start, finish = events[0], events[-1]
        assert start['event'] == 'replay_started' and finish['event'] == 'replay_finished'
        raw_bytes = (directory / 'report.model-raw.json').read_bytes()
        checked_bytes = (directory / 'report.checked.json').read_bytes()
        if sha(raw_bytes) != expected:
            raise ValueError('Pinned report changed; a new source audit is required')
        raw, checked = json.loads(raw_bytes), json.loads(checked_bytes)
        source = ROOT / 'runs' / start['source_run']
        if sha((source / 'events.jsonl').read_bytes()) != start['source_journal_sha256']:
            raise ValueError('Captured VM journal changed')
        digest = json.loads((source / 'report.private.json').read_bytes())['sample_sha256']
        selected = [r for r in events if r['event'] == 'operation_assertion_proposed']
        inventory = next(r for r in events if r['event'] == 'operation_assertion_catalog')['entries']
        decisions = [r for r in events if r['event'] == 'operation_assertion_decision']
        is_python = digest == profile['sample_sha256']
        allowed = PYTHON if is_python else DOTNET
        if {x['fact_id'] for x in inventory} != set(allowed):
            raise ValueError('Catalog differs from explicit audited source sites')
        if len(selected) != len(raw['claims']) or [r['claim'] for r in selected] != raw['claims']:
            raise ValueError('Proposed claim journal differs from raw report')
        audit = {'run_id': run_id, 'raw_report_sha256': expected, 'sample_sha256': digest,
                 'dataset_origin': 'public malware, development; captured-feature reporting ablation',
                 'method': 'Explicit source audit of narrow API assertions; not SLM self-review',
                 'human_reviewers': [], 'claims': []}
        mapping = {'schema_version': 1, 'sample_sha256': digest, 'profile_sha256': sha(profile_bytes),
                   'raw_report_sha256': expected, 'checked_report_sha256': sha(checked_bytes),
                   'reviewer': 'source-audit; no human/lecturer approval',
                   'method': 'Explicit one-operation-to-one-reference mapping after source inspection', 'claims': []}
        for event in selected:
            fact_id, claim = event['fact_id'], event['claim']
            refs = [{k:v for k,v in ref.items() if k != 'quote'} for ref in claim['evidence']]
            reason = (PYTHON[fact_id][1] if is_python else
                      'System.Net import, local WebClient constructor and source call at row ' + str(DOTNET[fact_id]) +
                      ' establish the path/destination or response-character-decoding assertion. No file contents or cryptographic decryption inferred.')
            audit['claims'].append({'claim_id': claim['id'], 'label': 'correct', 'grounded': True,
                                    'reviewer': 'source-audit; no human/lecturer approval',
                                    'truth_reference': refs, 'reason': reason})
            if is_python:
                unit = 'PY24-' + PYTHON[fact_id][0]
                mapping['claims'].append({'claim_id': claim['id'], 'atoms': [{'start': 0, 'end': len(claim['text']),
                    'unit_key': unit, 'reference_id': unit, 'label': 'correct', 'reason': reason, 'source_references': refs}]})
        score = claim_score(raw_bytes, checked, audit)
        out = ROOT / 'deliverables/real-demo-evidence/atomic-report-stage' / run_id
        write(ROOT / 'eval/adjudications' / (run_id + '-operation-source-audit.json'), audit)
        write(out / 'claim-score.json', score)
        normalized = atomic_score(profile_bytes, raw_bytes, checked_bytes, mapping) if is_python else None
        if normalized is not None:
            write(ROOT / 'eval/adjudications' / (run_id + '-atomic-mapping.json'), mapping)
            write(out / 'atomic-score.json', normalized)
        requests = [r for r in events if r['event'] == 'model_request']
        # Hash only request messages+schema, never publish the source-bearing payload.
        request_hashes = [sha(canonical({'messages':r['messages'], 'schema':r['schema']})) for r in requests]
        receipt = {'run_id': run_id, 'kind': 'real-slm-on-captured-vm-features-not-end-to-end-demo',
                   'source_run': start['source_run'], 'source_journal_sha256': start['source_journal_sha256'],
                   'sample_sha256': digest, 'model': {k:start['model'][k] for k in ('tag','digest','size_bytes','ollama_version')},
                   'source_manifest_sha256': start['source_manifest_sha256'],
                   'actual_reporter_source_sha256': start['source_files']['stealer_agent/operation_assertions.py'],
                   'legacy_reporter_field_note': 'These three historical journals name evidence_cards.py in reporter_source_sha256. '
                       'The actual operations reporter is independently identified by source_files and preserved in eval/reproductions/operation-assertions-v1/reporter.py. '
                       'Private journals are unchanged; later runner versions identify the selected reporter directly.',
                   'source_files': start['source_files'], 'raw_report_sha256': expected,
                   'private_journal_sha256': sha(events_bytes), 'checked_report_sha256': sha(checked_bytes),
                   'config': {k:start['config'][k] for k in ('num_ctx','num_predict','seed')},
                   'metrics': finish['metrics'], 'catalog_audited_correct': len(inventory),
                   'selected': len(selected), 'abstained_on_supported_operations': sum(not r['response']['include'] for r in decisions),
                   'decisions': [{'fact_id':r['fact_id'], 'include':r['response']['include']} for r in decisions],
                   'request_message_schema_sha256': request_hashes,
                   'raw_source_audit': score['raw'], 'atomic_score': normalized['raw'] if normalized else None,
                   'verdict': checked['verdict'], 'full_analysis_completed': False,
                   'limits': checked['limitations'], 'pending_analysis': checked['pending_analysis']}
        if 'think' in start['config']: receipt['config']['think'] = start['config']['think']
        write(out / 'receipt.json', receipt)
        receipts.append(receipt)
    py = [r for r in receipts if r['sample_sha256'] == profile['sample_sha256']]
    comparison = {'python_request_messages_and_schemas_identical': py[0]['request_message_schema_sha256'] == py[1]['request_message_schema_sha256'],
                  'source_snapshots_identical': len({r['source_manifest_sha256'] for r in receipts}) == 1,
                  'source_archive': 'private/report-source-snapshots/<manifest>/source.tar',
                  'archive_note': 'Archive assembled after runs, with every file verified against the hash recorded at run start.',
                  'experiments': [r['run_id'] for r in receipts], 'full_coursework_quality_gate_passed': False}
    write(ROOT / 'deliverables/real-demo-evidence/atomic-report-stage/comparison.json', comparison)
    print(json.dumps({'comparison': comparison, 'scores': [{'run':r['run_id'], 'selected':r['selected'],
        'elapsed_s':r['metrics']['elapsed_s'], 'atomic':r['atomic_score']} for r in receipts]}))


if __name__ == '__main__':
    main()
