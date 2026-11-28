"""Locate missed reference units relative to the actual projected generation windows.

Units have audited row ranges. Row availability is neither semantic support nor
proof of what the model used. This reproduces the pinned Python v10 diagnosis.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

from scripts.replay_card_report import reconstruct
from stealer_agent.journal import canonical, dump_json, verify_journal

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '20261127T230331_8bd30a1f'
EARLIER = '20261127T211223_9602dfdd'
REPLAY = '20261127T232149_05950420'


def read_events(directory):
    path = directory / 'events.jsonl'
    verify_journal(path)
    return [json.loads(s) for s in path.read_bytes().splitlines()]


def main():
    profile_path = ROOT / 'eval/reference_units/python2024.atomic-v2.json'
    profile = json.loads(profile_path.read_bytes())
    out = ROOT / 'deliverables/real-demo-evidence'
    score = json.loads((out / 'python2024-cards-v10-report-stage-atomic-score.json').read_bytes())
    digest = lambda data: hashlib.sha256(data).hexdigest()
    assert digest(profile_path.read_bytes()) == score['fingerprints']['profile_sha256']
    directory = ROOT / 'private/report-experiments' / REPLAY
    assert digest((directory / 'report.model-raw.json').read_bytes()) == score['fingerprints']['raw_report_sha256']
    events = read_events(directory)
    source_dir = ROOT / 'runs' / SOURCE
    assert digest((source_dir / 'events.jsonl').read_bytes()) == events[0]['source_journal_sha256']
    current = reconstruct(read_events(source_dir))
    historical = {**reconstruct(read_events(ROOT / 'runs' / EARLIER)), **current}
    eid = 'ev_a789dcd941044224'
    record = current[eid]
    windows = []
    for event in events:
        if event['event'] != 'model_request' or event['phase'] != 'card_generate':
            continue
        assert digest(canonical(event['messages'])) == event['messages_sha256']
        code = json.loads(event['messages'][-1]['content'])['code'].splitlines()
        present = set()
        for item in event['evidence']:
            if item['evidence_id'] != eid:
                continue
            for row in item['lines']:
                n, text = row['line'], row['text']
                assert record['line_map'][n] == text and f'{n} | {text}' in code
                present.add(n)
        windows.append(present)
    matched = set(score['raw']['matched_reference_ids'])
    kept = set(score['after_filter']['matched_reference_ids'])
    counts, rows = Counter(), []
    for unit in profile['units']:
        uid, required = unit['id'], set()
        for ref in unit['source_references']:
            original = historical[ref['evidence_id']]
            assert original['sample_sha256'] == record['sample_sha256'] == profile['sample_sha256']
            for n in range(ref['line'], ref['end_line'] + 1):
                # Output record IDs differ per session. Match the actual projected rows.
                assert n in original['line_map']
                if n in record['line_map']:
                    assert original['line_map'][n] == record['line_map'][n]
                    assert original['line_metadata'][n] == record['line_metadata'][n]
                required.add(n)
        if uid in matched:
            category = 'kept' if uid in kept else 'lost_at_review'
        elif not required.issubset(record['line_map']):
            category = 'missing_from_retrieval'
        elif any(required <= window for window in windows):
            category = 'all_rows_in_one_request_but_no_matching_claim'
        elif required <= set().union(*windows):
            category = 'rows_split_between_requests'
        else:
            category = 'retrieved_rows_missing_from_requests'
        counts[category] += 1
        rows.append({'unit': uid, 'category': category, 'required_rows': len(required),
                     'full_generation_windows': [i for i, window in enumerate(windows, 1) if required <= window]})
    result = {'source_run': SOURCE, 'replay': REPLAY, 'raw_report_sha256': score['fingerprints']['raw_report_sha256'],
              'profile_sha256': score['fingerprints']['profile_sha256'], 'counts': dict(counts), 'units': rows,
              'scope': 'Presence of declared reference rows in logged generator messages. Does not establish causality, semantic correctness or complete attention to the input.'}
    dump_json(out / 'python2024-cards-v10-missed-unit-exposure.json', result)
    print(json.dumps(result['counts']))


if __name__ == '__main__':
    main()
