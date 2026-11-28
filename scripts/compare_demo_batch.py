"""Check that real VM runs use the same model, sources and controller settings."""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.stability import calculate as stability
from scripts.report_experiment_receipt import summarize
from stealer_agent.journal import dump_json


def compare(run_ids):
    if len(set(run_ids)) != len(run_ids):
        raise ValueError('A run can only be counted once')
    sample_lock = json.loads((ROOT/'config/public-samples.json').read_bytes())['samples']
    reports = defaultdict(list)
    rows = []
    for name in run_ids:
        directory = (ROOT/'runs'/name).resolve(strict=True)
        if directory.name != name or directory.parent != (ROOT/'runs').resolve():
            raise ValueError('Expected a run ID')
        row = summarize(directory)
        sample = row['sample']
        if (row['evidence_kind'] != 'real-public-malware-local-slm-vm' or
                sample_lock[sample]['sha256'] != row['sample_sha256']):
            raise ValueError('Batch requires hash-verified public VM samples')
        rows.append(row)
        if row['status'].startswith('completed'):
            reports[row['sample_sha256']].append(json.loads((directory/'report.private.json').read_bytes()))
    fingerprints = {(r['model']['digest'], r['source_manifest_sha256'], r['config_sha256_excluding_sample']) for r in rows}
    if len(fingerprints) != 1 or not all(next(iter(fingerprints))):
        raise ValueError('Different settings, code or model in batch')
    # No favorable selection among >3 repeats. Request an explicit series of three.
    repeated = {sample: stability(items) for sample, items in reports.items() if len(items) == 3}
    tools = set()
    for r in rows:
        if r['status'].startswith('completed'):
            tools.update(r['successful_tools'])
    attempted = {r['sample_sha256'] for r in rows}
    return {'kind':'same-revision-end-to-end-vm-demo', 'runs':rows,
            'distinct_attempted_samples_with_terminal_journal':len(attempted),
            'distinct_completed_samples':len(reports), 'at_least_three_samples_with_journal':len(reports) >= 3,
            'successful_analysis_tools':sorted(tools), 'stable_series_by_sample':repeated,
            'stability_definition':'Exact intersection/union on three distinct completed runs for a single sample.',
            'scope':'Sample coverage and repeatability only. Semantic quality requires separate source adjudication.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.run)
    dump_json(args.output, result)
    print(json.dumps({key:result[key] for key in ('distinct_completed_samples', 'successful_analysis_tools', 'stable_series_by_sample')}))
