"""Real SLM on captured VM features for report ablations; NOT an end-to-end demo."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.evidence_cards import create_card_report
from stealer_agent.journal import Journal, canonical, dump_json, verify_journal, record_model_request
from stealer_agent.telemetry import available_memory_bytes
from stealer_agent.transport import OllamaClient
from stealer_agent.model_projection import ModelEvidenceView


def select_reporter(method, measured_revision=False):
    source_files = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted((ROOT / 'stealer_agent').glob('*.py'))}
    if measured_revision:
        if method != 'operations':
            raise ValueError('Measured revision is only defined for the operations ablation')
        folder = ROOT / 'eval/reproductions/operation-assertions-v1'
        manifest = json.loads((folder / 'manifest.json').read_text(encoding='utf-8'))
        for name, expected in manifest.items():
            path = folder / 'reporter.py' if name == 'stealer_agent/operation_assertions.py' else ROOT / name
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError('Measured-revision dependency changed: ' + name)
        spec = importlib.util.spec_from_file_location('stealer_agent.operation_assertions_reproduction', folder / 'reporter.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.create_operation_report, manifest, 'eval/reproductions/operation-assertions-v1/reporter.py'
    if method == 'operations':
        from stealer_agent.operation_assertions import create_operation_report
        return create_operation_report, source_files, 'stealer_agent/operation_assertions.py'
    return create_card_report, source_files, 'stealer_agent/evidence_cards.py'


def reconstruct(events):
    evidence = {}
    view = ModelEvidenceView()
    for event in events:
        if event['event'] == 'observation':
            view.learn(event['model_visible'])
    for event in events:
        if event['event'] != 'observation':
            continue
        clean = view.observation(event['model_visible'])
        eid = clean['evidence_id']
        record = evidence.setdefault(eid, {**copy.deepcopy(clean), 'line_map': {}})
        record['line_map'].update({r['line']: r['text'] for r in clean['lines']})
        record.setdefault('line_metadata', {}).update({r['line']: {'source_line': r.get('source_line')}
                                                      for r in clean['lines']})
        record['latest_lines'] = [r['line'] for r in clean['lines']]
        for link in clean.get('context_links', []):
            if link not in record.setdefault('context_links', []):
                record['context_links'].append(link)
        for fact in clean.get('operation_facts', []):
            if fact not in record.setdefault('operation_facts', []):
                record['operation_facts'].append(fact)
        if 'search_groups' in clean:
            for group in clean['search_groups']:
                anchor = group['anchor_line']
                record.setdefault('focus_groups', []).append(sorted(group['lines'], key=lambda n: (abs(n-anchor), n)))
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--model')
    parser.add_argument('--cards', type=int, default=3)
    parser.add_argument('--method', choices=['cards', 'operations'], default='cards',
                        help='operations is a narrow reporting ablation, not a full analysis profile')
    parser.add_argument('--measured-revision', action='store_true',
                        help='Replay the archived operation reporter; verify every dependency hash first')
    parser.add_argument('--no-api-guidance', action='store_true', help='Controlled ablation; same v5 prompts without API reference notes')
    args = parser.parse_args()
    reporter, source_files, reporter_path = select_reporter(args.method, args.measured_revision)
    directory = (ROOT / 'runs' / args.run).resolve(strict=True)
    if directory.parent != (ROOT / 'runs').resolve():
        raise ValueError('Source must be a run ID under runs/')
    path = directory / 'events.jsonl'
    verify_journal(path)
    events = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
    source_result = json.loads((directory / 'report.private.json').read_text(encoding='utf-8'))
    evidence = reconstruct(events)
    cfg = json.loads(args.config.read_text(encoding='utf-8'))
    if args.model:
        cfg['model'] = args.model
    llm = OllamaClient(cfg)
    model = llm.inspect()
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '_' + uuid.uuid4().hex[:8]
    journal = Journal(ROOT / 'private/report-experiments' / run_id)
    metrics = {'model_calls': 0, 'prompt_tokens': 0, 'completion_tokens': 0, 'minimum_free_ram_bytes': None}
    journal.append('replay_started', evidence_kind='real-slm-on-captured-vm-features-not-end-to-end-demo',
                   source_run=args.run, source_journal_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                   model=model, config={k:v for k,v in cfg.items() if 'token' not in k},
                   config_file_sha256=hashlib.sha256(args.config.read_bytes()).hexdigest(),
                   source_files=source_files, source_manifest_sha256=hashlib.sha256(canonical(source_files)).hexdigest(),
                   reporter_implementation_path=reporter_path,
                   reporter_source_sha256=hashlib.sha256((ROOT / reporter_path).read_bytes()).hexdigest())
    journal.append('replay_settings', max_cards=args.cards, api_guidance=not args.no_api_guidance, method=args.method)

    def invoke(messages, schema, phase, request_evidence):
        free = available_memory_bytes()
        if free is not None:
            previous = metrics['minimum_free_ram_bytes']
            metrics['minimum_free_ram_bytes'] = free if previous is None else min(previous, free)
            if free < 256 * 1024 * 1024:
                llm.unload()
                raise RuntimeError('ResourceBudgetExceeded in captured-feature experiment')
        step = metrics['model_calls'] + 1
        record_model_request(journal,step=step,phase=phase,messages=messages,schema=schema,evidence=request_evidence)
        response, usage = llm.chat(messages, schema)
        metrics['model_calls'] += 1
        for key in ('prompt_tokens', 'completion_tokens'):
            value = usage.get(key)
            metrics[key] = metrics[key] + value if metrics[key] is not None and isinstance(value, int) else None
        journal.append('model_response', step=step, phase=phase, response=response, metrics=usage)
        print(json.dumps({'call': step, 'phase': phase, 'returned_claims': len(response.get('claims', []))}), flush=True)
        return response

    start = time.perf_counter()
    raw, checked = reporter(evidence, source_result['sample_sha256'], invoke, journal,
                                      max_cards=args.cards, api_guidance=not args.no_api_guidance)
    metrics['elapsed_s'] = round(time.perf_counter() - start, 4)
    dump_json(journal.directory / 'report.model-raw.json', raw)
    dump_json(journal.directory / 'report.checked.json', checked)
    journal.append('replay_finished', metrics=metrics, verdict=checked['verdict'],
                   accepted_claims=len(checked['claims']), rejected_claims=len(checked['rejected_claims']))
    print(json.dumps({'directory': str(journal.directory), 'metrics': metrics, 'verdict': checked['verdict'],
                      'claims': len(checked['claims']), 'kind': 'captured-feature-ablation-not-live-demo'}))


if __name__ == '__main__':
    main()
