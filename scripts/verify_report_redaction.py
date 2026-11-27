"""Check local rendering against saved real reports; never rewrite original runs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import dump_json, utc_now, verify_journal
from stealer_agent.redaction import collect_literals, string_values
from stealer_agent.reporting import write_report


def verify(run_id):
    directory = (ROOT/'runs'/run_id).resolve(strict=True)
    if directory.parent != (ROOT/'runs').resolve():
        raise ValueError('Expected one local run ID')
    verify_journal(directory/'events.jsonl')
    private_path = directory/'report.private.json'
    before = hashlib.sha256(private_path.read_bytes()).hexdigest()
    result = json.loads(private_path.read_text(encoding='utf-8'))
    events = [json.loads(line) for line in (directory/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    context = [row['text'] for e in events if e['event'] == 'observation'
               for row in e['model_visible'].get('lines', [])]
    literals, truncated = collect_literals([*context, *string_values(result)])
    visible_literals = {s for s in literals if any(s in text for text in string_values(result))}
    target = ROOT/'private/report-experiments/redaction-v1'/run_id
    target.mkdir(parents=True, exist_ok=True)
    write_report(target, result, redaction_context=context)
    rendered = [(target/name).read_text(encoding='utf-8') for name in ('report.redacted.json', 'report.md')]
    # Inspect decoded JSON too, so escaping cannot hide a remaining literal.
    rendered.extend(string_values(json.loads(rendered[0])))
    remaining = sum(any(s in text for text in rendered) for s in visible_literals)
    if remaining:
        raise ValueError('Detected credential literal remains in rendered view; values withheld')
    assert hashlib.sha256(private_path.read_bytes()).hexdigest() == before
    return {'run_id': run_id, 'sample_sha256': result['sample_sha256'],
            'original_private_report_sha256': before,
            'original_report_unchanged': True, 'detected_literal_count': len(literals),
            'literals_present_in_private_report': len(visible_literals),
            'known_literals_remaining_in_rendered_view': remaining,
            'scan_truncated': truncated, 'public_export_approved': False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = {'checked_at': utc_now(), 'kind': 'saved-real-report-render-check',
               'runs': [verify(name) for name in args.run],
               'limits': ['This re-renders saved reports; no new model/tool analysis occurred.',
                          'Known literals/patterns only; not proof that all possible secrets were detected.',
                          'Outputs remain private; source, prose and secret values are excluded from this receipt.']}
    dump_json(args.output, receipt)
    print(json.dumps({'output': str(args.output), 'runs_checked': len(receipt['runs']),
                      'known_literals_remaining': sum(r['known_literals_remaining_in_rendered_view'] for r in receipt['runs'])}))


if __name__ == '__main__':
    main()
