"""Scan a previously frozen rule against the clean challenge, twice, without an SLM."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from sync_vm import ROOT, SSH, DEST
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import verify_journal, dump_json, utc_now
from stealer_agent.yara_corpus import validate_scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source_run', type=Path)
    args = parser.parse_args()
    run = args.source_run.resolve(strict=True)
    verify_journal(run/'events.jsonl')
    events = [json.loads(s) for s in (run/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    frozen = next(e for e in events if e['event'] == 'rules_frozen')
    rule = run/'generated.yar'
    source = rule.read_text(encoding='utf-8')
    digest = hashlib.sha256(rule.read_bytes()).hexdigest()
    if digest != frozen['rule_sha256']:
        raise ValueError('Frozen rule file changed')
    if any(e['event'] == 'model_request' and e['sequence'] > frozen['sequence'] for e in events):
        raise ValueError('Model was called after the rule freeze')
    manifest_path = ROOT/'eval/corpora/real-yara-challenge-v2.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    subprocess.run(['scp', *SSH, str(rule), DEST+':/home/labadmin/frozen-challenge.yar'], check=True)
    code = '''import hashlib,json,pathlib,sys
sys.path.insert(0,'/opt/stealer-lab')
from vm_tools.runner import bounded_process
root=pathlib.Path('/opt/stealer-lab')
manifest=root/'private/evaluation/real-yara-challenge-v2.json'
assert hashlib.sha256(manifest.read_bytes()).hexdigest()==MANIFEST_DIGEST
source=pathlib.Path('/home/labadmin/frozen-challenge.yar').read_bytes()
assert hashlib.sha256(source).hexdigest()==RULE_DIGEST
rule=root/'private/evaluation'/('frozen-'+RULE_DIGEST+'.yar')
if rule.exists(): assert rule.read_bytes()==source
else: rule.write_bytes(source)
results=[]
for repeat in range(2):
    results.append(json.loads(bounded_process(['/usr/bin/sudo','-u','analyst','/usr/bin/env','PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps','/usr/bin/python3','-m','vm_tools.yara_worker',str(rule),str(manifest),'holdout',str(root/'samples')],root/'private/tool-evidence/work',timeout=90,max_bytes=50000,memory_limit=True)))
print(json.dumps(results))
'''.replace('MANIFEST_DIGEST', repr(hashlib.sha256(manifest_path.read_bytes()).hexdigest())).replace('RULE_DIGEST', repr(digest))
    output = subprocess.run(['ssh', *SSH, DEST, 'sudo env PYTHONPATH=/opt/stealer-lab:/opt/stealer-lab/deps /usr/bin/python3 -'],
                            input=code, text=True, capture_output=True, check=True, timeout=200)
    results = json.loads(output.stdout)
    for result in results:
        validate_scan(result, manifest, 'holdout', source)
    first = results[0]
    previous = set(manifest['prior_clean_hashes'])
    fresh = [r for r in first['results'] if r['sha256'] not in previous]
    receipt = {'recorded_at': utc_now(), 'source_run': run.name, 'rule_sha256': digest,
               'rules_modified': False, 'new_model_calls': 0, 'sample_execution': False,
               'result': first, 'independent_replay_equal': results[0] == results[1],
               'fresh_negative_count': len(fresh), 'fresh_false_positives': sum(r['matched'] for r in fresh),
               'coursework_accepted': False, 'limitations': manifest['limits']}
    destination = ROOT/'deliverables/real-demo-evidence'/('yara-challenge-'+run.name+'.json')
    dump_json(destination, receipt)
    print(json.dumps({'receipt': str(destination), 'negative_count': first['negative_count'],
                      'false_positives': sum(r['matched'] for r in first['results']),
                      'fpr': first['fpr'], 'replay_equal': receipt['independent_replay_equal']}))


if __name__ == '__main__':
    main()
