"""Export a field-allowlisted receipt of real runs; retain full private logs locally."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stealer_agent.journal import dump_json, utc_now, verify_journal

ROOT = Path(__file__).resolve().parents[1]


def main():
    manifest = json.loads((ROOT / 'config/public-samples.json').read_text(encoding='utf-8'))
    result = {'created_at': utc_now(), 'scope': 'real public samples, static VM tools, local SLM',
              'quality_acceptance': False, 'runs': []}
    for run_id in sys.argv[1:]:
        if Path(run_id).name != run_id:
            raise ValueError('Expected run ID only')
        folder = ROOT / 'runs' / run_id
        report = json.loads((folder / 'report.private.json').read_text(encoding='utf-8'))
        expected = manifest['samples'][report['sample']]['sha256']
        assert expected == report['sample_sha256']
        assert report['evidence_kind'] == 'real-public-malware-local-slm-vm'
        journal = folder / 'events.jsonl'
        count = verify_journal(journal)
        events = [json.loads(line) for line in journal.read_text(encoding='utf-8').splitlines()]
        trace = []
        for event in events:
            if event['event'] == 'observation':
                raw = event['raw']
                trace.append({'sequence': event['sequence'], 'timestamp': event['timestamp'],
                              'step': event['step'], 'tool': raw['tool'], 'status': raw['status'],
                              'backend': raw['backend']})
        record = {key: report[key] for key in ('run_id', 'sample', 'sample_sha256', 'status',
                    'successful_tools', 'metrics', 'acceptance', 'file_facts', 'evidence_kind')}
        record.update(verdict=report['analysis']['verdict'],
                      accepted_claims=len(report['analysis']['claims']),
                      rejected_claims=len(report['analysis']['rejected_claims']),
                      model={key: report['model'][key] for key in ('tag','digest','details','ollama_version')},
                      journal_events_verified=count, tool_trace=trace,
                      original_journal_sha256=hashlib.sha256(journal.read_bytes()).hexdigest(),
                      original_report_sha256=hashlib.sha256((folder/'report.private.json').read_bytes()).hexdigest(),
                      source_manifest_sha256=next(e['manifest_sha256'] for e in events if e['event']=='source_version'),
                      export_note='Selected fields only; not a replacement hash chain or full raw journal')
        result['runs'].append(record)
    if not result['runs']:
        raise ValueError('Supply real run IDs')
    dump_json(ROOT/'deliverables/real-demo-evidence/receipt.json', result)
    dump_json(ROOT/'evidence/local/real-demo-latest.json', result)
    print(json.dumps({'runs': [r['run_id'] for r in result['runs']], 'journal_chains_verified': True}))


if __name__ == '__main__':
    main()
