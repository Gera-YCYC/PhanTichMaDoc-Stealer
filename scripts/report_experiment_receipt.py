"""Export an allowlisted metadata receipt, never source excerpts or model text."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import canonical, dump_json, utc_now, verify_journal


def config_digest(config):
    settings = {k: v for k, v in config.items() if k != 'expected_sample_sha256'}
    return hashlib.sha256(canonical(settings)).hexdigest()


def additional_measurements(directory, analysis, journal_hash):
    from stealer_agent.yara_case import RULES, select_row
    from stealer_agent.yara_corpus import validate_scan

    result = {}
    path = directory/'host-resources.json'
    sample = analysis['sample_sha256']
    if path.exists():
        obs = json.loads(path.read_bytes())
        if (obs['run_id'], obs['sample_sha256'], obs['journal_sha256'], obs['model_digest']) != (
                directory.name, sample, journal_hash, analysis['model']['digest']):
            raise ValueError('Memory observation and journal identities differ')
        m = obs['measurements']
        numbers = ('target_interval_s','samples','ram_samples','gpu_samples',
                   'max_sample_gap_s','minimum_available_ram_bytes')
        numeric = {k: m[k] for k in numbers}
        if any(v is not None and (type(v) not in (int, float) or not math.isfinite(v) or v < 0)
               for v in numeric.values()):
            raise ValueError('Invalid resource measurement')
        for key in ('gpu_peak_used_mib_by_index','gpu_total_mib_by_index'):
            if not all(i.isascii() and i.isdigit() and type(v) is int and v >= 0 for i,v in m[key].items()):
                raise ValueError('Invalid GPU index or memory measurement')
            numeric[key] = m[key]
        result['sampled_host_resources'] = numeric
    scans = []
    for path in sorted(directory.glob('yara/scan_*/result.json')):
        public = json.loads(path.read_bytes())
        log = path.parent/'events.jsonl'
        n = verify_journal(log)
        rows = [json.loads(line) for line in log.read_bytes().splitlines()]
        saved = rows[-1].get('result')
        if (rows[-1]['event'] != 'rescan_finished' or public !=
                {**saved, 'scan_journal_events': n, 'scan_journal_sha256': hashlib.sha256(log.read_bytes()).hexdigest()}
                or saved['sample_sha256'] != sample or saved['analysis_run'] != directory.name
                or saved['analysis_journal_sha256'] != journal_hash or saved['model'] != analysis['model']['tag']
                or saved['analysis_verdict'] != analysis['analysis']['verdict']):
            raise ValueError('YARA attachment differs from the journal or the analyzed sample')
        pages = [e['raw'] for e in rows if e['event'] in ('vm_observation','evidence_page')]
        identifiers = {(p['evidence_id'],p['output_sha256'],p['sample_sha256']) for p in pages}
        lines = [line for p in pages for line in p['lines']]
        if (len(identifiers) != 1 or pages[0]['sample_sha256'] != sample or pages[0]['tool'] != 'test_yara'
                or [r['line'] for r in lines] != list(range(1, pages[0]['total_lines'] + 1))):
            raise ValueError('Incomplete or mixed YARA output pages')
        generation, rule_name = RULES[saved['model']]
        corpus = json.loads((ROOT/'eval/corpora/real-yara-development-v3.json').read_bytes())
        rule = (ROOT/'rules'/rule_name).read_text(encoding='utf-8')
        scan = validate_scan(json.loads(''.join(r['text'] for r in lines)), corpus, 'training', rule)
        match = select_row(scan, analysis['sample'], sample)
        if (saved['rule_names'] != match['rules'] or saved['matched'] is not match['matched']
                or saved['generation_run'] != generation or saved['rule_sha256'] != scan['rule_sha256']):
            raise ValueError('YARA result differs from original VM output or frozen rule')
        scans.append({'generation_run': generation, 'rule_file': rule_name, 'rule_sha256': scan['rule_sha256'],
                      'matched': match['matched'], 'rule_names': match['rules'],
                      'partition': scan['corpus'], 'partition_size': len(scan['results']),
                      'scan_journal_sha256': public['scan_journal_sha256'], 'scan_journal_events': n})
    if scans:
        result['subsequent_vm_yara_scans'] = scans
    return result


def summarize(directory):
    path = directory / 'events.jsonl'
    count = verify_journal(path)
    events = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
    result = json.loads((directory / 'report.private.json').read_text(encoding='utf-8'))
    if (events[-1]['event'] != 'run_finished' or events[-1]['result'] != result
            or result['run_id'] != directory.name):
        raise ValueError('Terminal journal event and saved report must describe the same run')
    raw_path = directory / 'report.model-raw.json'
    raw = json.loads(raw_path.read_text(encoding='utf-8')) if raw_path.is_file() else None
    source = next(e for e in events if e['event'] == 'source_version')
    started = next(e for e in events if e['event'] == 'run_started')
    analysis = result['analysis']
    responses = Counter(e.get('phase', 'react') for e in events if e['event'] == 'model_response')
    requests = {(e['step'], e.get('phase')) for e in events if e['event'] == 'model_request'}
    paired = all((e['step'], e.get('phase')) in requests for e in events if e['event'] == 'model_response')
    operations = result.get('typed_operations', [])
    observed = {}
    backends = set()
    for event in events:
        if event['event'] != 'observation':
            continue
        raw_observation = event.get('raw', {})
        if raw_observation.get('operation_backend'):
            backends.add(raw_observation['operation_backend'])
        if raw_observation.get('status') != 'ok':
            continue
        key = (raw_observation.get('evidence_id'), raw_observation.get('sample_sha256'), raw_observation.get('output_sha256'))
        observed.setdefault(key, set()).update(row['line'] for row in raw_observation.get('lines', []))
    for fact in operations:
        payload = {k:v for k,v in fact.items() if k != 'fact_id'}
        assert fact['fact_id'] == 'op_' + hashlib.sha256(canonical(payload)).hexdigest()[:16]
        key = (fact['evidence_id'], fact['sample_sha256'], fact['output_sha256'])
        assert key[1] == result['sample_sha256']
        assert all(n in observed.get(key, set()) for ref in fact['ranges'] for n in range(ref['line'], ref['end_line']+1))
    channel_features = []
    for feature in result.get('channel_shapes', []):
        if (set(feature) != {'kind', 'credential_shape_present', 'evidence_id', 'line', 'sample_sha256', 'output_sha256'}
                or feature['kind'] != 'discord_webhook_literal' or feature['credential_shape_present'] is not True
                or feature['sample_sha256'] != result['sample_sha256'] or type(feature['line']) is not int):
            raise ValueError('Unrecognized channel shape or unexpected data')
        if not any(e['event'] == 'observation' and e['raw']['status'] == 'ok'
                   and e['raw']['sample_sha256'] == feature['sample_sha256']
                   and e['raw']['output_sha256'] == feature['output_sha256']
                   and e['raw']['evidence_id'] == feature['evidence_id']
                   and 1 <= feature['line'] <= e['raw']['total_lines'] and feature in e['raw'].get('channel_shapes', [])
                   for e in events):
            raise ValueError('Channel shape has no matching successful VM observation')
        channel_features.append(feature)
    decisions = [e for e in events if e['event'] == 'operation_review_decision']
    return {
        **additional_measurements(directory, result, hashlib.sha256(path.read_bytes()).hexdigest()),
        'run_id': result['run_id'], 'sample': result['sample'], 'sample_sha256': result['sample_sha256'],
        'evidence_kind': result.get('evidence_kind'), 'status': result['status'],
        'source_manifest_sha256': source['manifest_sha256'],
        'model': {k: result['model'].get(k) for k in ('tag', 'digest', 'size_bytes', 'details')},
        'settings': {k: started['config'].get(k) for k in ('max_steps', 'num_ctx', 'num_predict', 'seed', 'think',
                    'report_mode', 'max_report_cards', 'min_code_searches', 'evidence_chars', 'code_evidence_chars',
                    'review_operations', 'semantic_review', 'recover_empty_searches', 'review_techniques', 'occurrence_order')},
        'config_sha256_excluding_sample': config_digest(started['config']),
        'operation_review': {'decisions':len(decisions), 'selected':sum(e['selected'] is True for e in decisions)},
        'successful_tools': result['successful_tools'], 'metrics': result['metrics'],
        'journal': {'events': count, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                    'chain_verified': True, 'every_response_has_request': paired},
        'model_responses_by_phase': dict(responses),
        'report_method': analysis.get('report_method', 'not_reached_or_legacy'),
        'raw_report_available': raw is not None,
        'raw_report_sha256': hashlib.sha256(raw_path.read_bytes()).hexdigest() if raw else None,
        'proposed_claims': len(raw['claims']) if raw else None,
        'accepted_claims': len(analysis.get('claims', [])),
        'rejected_claims': len(analysis.get('rejected_claims', [])),
        'card_count': analysis.get('card_count'), 'skipped_import_cards': analysis.get('skipped_import_cards'),
        'verdict': analysis['verdict'], 'proposed_verdict': analysis.get('proposed_verdict'),
        'verdict_support_missing': analysis.get('verdict_support_missing'),
        'verdict_support_invalid': analysis.get('verdict_support_invalid'),
        'error_classes': [e['error'].split(':', 1)[0] for e in events if e['event'] == 'run_error'],
        'quality_metrics': None,
        'tool_channel_shapes': channel_features,
        'reviewed_techniques': [{'technique_id': c['technique_id'],
                                'citations': [{k: ref[k] for k in ('evidence_id','line','end_line') if k in ref}
                                              for ref in c['evidence']]}
                               for c in analysis.get('claims',[]) if c['kind'] == 'attack'],
        'typed_operations': {'count':len(operations), 'counts_by_operation':dict(Counter(f['operation'] for f in operations)),
                             'backends': sorted(backends), 'fact_hashes_and_cited_rows_verified': True,
                             'used_to_adjudicate_slm_claims': False,
                             'semantic_accuracy_score': None},
        'limits': ['Tool success and valid hash chain do not prove semantic accuracy.',
                   'Raw source, endpoints, credentials and model prose are intentionally excluded.',
                   'This receipt is not an independent grade or a full-coursework acceptance.'],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for name in args.run:
        directory = (ROOT / 'runs' / name).resolve(strict=True)
        if directory.parent != (ROOT / 'runs').resolve():
            raise ValueError('Run must be a single directory ID under runs/')
        rows.append(summarize(directory))
    receipt = {'created_at': utc_now(), 'kind': 'real-local-model-vm-experiment-metadata', 'runs': rows}
    dump_json(args.output, receipt)
    print(json.dumps({'output': str(args.output), 'runs': len(rows),
                      'statuses': [r['status'] for r in rows]}))


if __name__ == '__main__':
    main()
