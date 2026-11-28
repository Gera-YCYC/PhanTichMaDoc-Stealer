"""Rescan a registered analysis sample with a frozen project rule in the VM."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
from .journal import Journal, dump_json, verify_journal
from .yara_corpus import corpus_digest, read_json_evidence, validate_scan

RULES = {
    'qwen2.5-coder:7b': ('yara_real_67d77a7d68ac', 'yara-v3-qwen7b.yar'),
    'qwen3:8b': ('yara_real_4054c42e1321', 'yara-v3-qwen8b.yar'),
}


def read(path):
    return json.loads(path.read_bytes())


def select_row(scan, sample, digest):
    rows = [r for r in scan['results'] if r['sha256'] == digest and r['sample'] == sample]
    if len(rows) != 1:
        raise ValueError('Expected one scanned file matching the analysis identity')
    row = rows[0]
    if (type(row['matched']) is not bool or not isinstance(row['rules'], list)
            or any(not re.fullmatch(r'LabCorpus_[0-9]{2}', name) for name in row['rules'])
            or row['matched'] != bool(row['rules'])):
        raise ValueError('Invalid YARA result for the file')
    return row


def scan_case(folder, vm):
    log = folder / 'events.jsonl'
    verify_journal(log)
    events = [json.loads(line) for line in log.read_bytes().splitlines()]
    report = read(folder / 'report.private.json')
    if (events[-1]['event'] != 'run_finished' or events[-1]['result'] != report
            or report['run_id'] != folder.name or report.get('evidence_kind') != 'real-public-malware-local-slm-vm'):
        raise ValueError('A terminal journal and matching public-sample analysis are required')
    sample, digest = report['sample'], report['sample_sha256']
    if read(ROOT/'config/public-samples.json')['samples'].get(sample, {}).get('sha256') != digest:
        raise ValueError('Analysis sample is not in the hash-pinned project set')
    tag = report['model']['tag']
    origin, name = RULES[tag]
    generation = ROOT/'deliverables/real-demo-evidence/yara-runs'/origin/'receipt.json'
    frozen = read(generation)
    rule_file = ROOT/'rules'/name
    source = rule_file.read_text(encoding='utf-8')
    manifest = read(ROOT/'eval/corpora/real-yara-development-v3.json')
    partition = 'training'
    if (frozen['run_id'] != origin or frozen['model'] != tag
            or frozen['model_digest'] != report['model']['digest'] or frozen['independent_replay_equal'] is not True):
        raise ValueError('Frozen rule generation has incompatible provenance')
    original = validate_scan(frozen['development'], manifest, partition, source)
    reference = select_row(original, sample, digest)
    health = vm.inspect()
    backend = health['tools']['test_yara']
    if not backend['available'] or backend['profiles'].get('real-v3', {}).get('corpora_sha256') != corpus_digest(manifest):
        raise ValueError('Install the real-v3 YARA corpus in this VM before running the optional rescan')
    journal = Journal(folder/'yara'/('scan_' + uuid4().hex[:12]))
    journal.append('rescan_started', analysis_run=folder.name, analysis_journal_sha256=sha256(log.read_bytes()).hexdigest(),
                   model=tag, generation_run=origin, generation_receipt_sha256=sha256(generation.read_bytes()).hexdigest(),
                   corpus_sha256=corpus_digest(manifest), rule_sha256=original['rule_sha256'], sample_sha256=digest)
    observation = vm.call('test_yara', {'sample': sample, 'rule': source, 'corpus': partition, 'profile': 'real-v3'})
    journal.append('vm_observation', raw=observation)
    if (observation.get('tool') != 'test_yara' or observation.get('sample') != sample
            or observation.get('sample_sha256') != digest or observation.get('status') != 'ok'):
        raise ValueError('Scan failed or returned another analysis identity')
    scan = validate_scan(read_json_evidence(vm, observation, journal), manifest, partition, source)
    row = select_row(scan, sample, digest)
    result = {
        'analysis_run': folder.name, 'analysis_journal_sha256': sha256(log.read_bytes()).hexdigest(),
        'sample_sha256': digest, 'analysis_verdict': report['analysis']['verdict'],
        'analysis_status': report['status'], 'generation_run': origin, 'model': tag,
        'rule_file': name, 'rule_sha256': scan['rule_sha256'], 'yara_version': scan['yara_version'],
        'scan_id': journal.directory.name, 'corpus_sha256': scan['corpora_sha256'],
        'target_representation': scan['target_representation'], 'dataset_partition': partition,
        'matched': row['matched'], 'rule_names': row['rules'], 'same_result_as_frozen_scan': row == reference,
        'files_scanned_in_partition': len(scan['results']), 'new_model_calls': 0,
    }
    journal.append('rescan_finished', result=result)
    result['scan_journal_events'] = verify_journal(journal.path)
    result['scan_journal_sha256'] = sha256(journal.path.read_bytes()).hexdigest()
    dump_json(journal.directory/'result.json', result)
    rel_rule = Path(os.path.relpath(rule_file, journal.directory)).as_posix()
    description = 'khớp ' + ', '.join(row['rules']) if row['matched'] else 'không khớp luật nào'
    doc = ['# Kết quả phân tích và phát hiện', '',
           f"Run `{folder.name}`. SHA-256 mẫu `{digest}`.", '',
           f"Agent kết luận `{result['analysis_verdict']}`. "
           "Mở [báo cáo phân tích](../../report.md) để xem hành vi, IOC, ATT&CK và trích dẫn. "
           f"Lần quét YARA cho kết quả **{description}**.", '',
           f"VM đã chạy YARA {scan['yara_version']} trên byte gốc của {len(scan['results'])} tệp cùng phân vùng. "
           "Dòng trên là kết quả của đúng mẫu đã phân tích. Mẫu thuộc bộ phát triển luật.", '',
           f"Luật do {tag} sinh trong lượt `{origin}`, được cố định trước lần quét này. "
           f"SHA-256 luật `{scan['rule_sha256']}`. [Mở tệp luật]({rel_rule}) · [Biên bản lần quét](result.json).", '']
    (journal.directory/'ket-qua.md').write_text('\n'.join(doc), encoding='utf-8')
    return journal.directory


def main():
    from .transport import ToolClient
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, help='Existing public demo run ID')
    args = parser.parse_args()
    if not re.fullmatch(r'\d{8}T\d{6}_[0-9a-f]{8}', args.run):
        parser.error('Expected a run ID')
    folder = (ROOT/'runs'/args.run).resolve(strict=True)
    if folder.parent != (ROOT/'runs').resolve():
        parser.error('Run is outside the project')
    cfg = read(ROOT/'config/host.example.json')
    token = os.environ.get(cfg['token_env']) or (ROOT/'config/lab.token').read_text(encoding='utf-8-sig').strip()
    print(scan_case(folder, ToolClient(cfg, token))/'ket-qua.md')


if __name__ == '__main__':
    main()
