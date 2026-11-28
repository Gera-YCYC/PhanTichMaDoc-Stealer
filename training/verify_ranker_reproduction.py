"""Re-train on the frozen numeric corpus and compare against the deployed ranker."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import canonical, dump_json, utc_now


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reproduce(output):
    original = ROOT / 'training/experiments/20261127T153436999877Z'
    deployed = ROOT / 'vm_tools/code_ranker.json'
    fresh_root = ROOT / 'private/ranker-reproduction'
    process = subprocess.run([sys.executable, str(ROOT / 'training/train_ranker.py'),
                              '--output', str(fresh_root)], capture_output=True, check=True)
    run = json.loads(process.stdout)
    repeat = fresh_root / run['run_id']
    first = json.loads((original / 'receipt.json').read_bytes())
    models = [json.loads((folder / 'model.json').read_bytes()) for folder in (original, repeat)]
    # Run ID changes each time by design. All inference parameters, feature
    # names, dataset identity and other serialized fields must match exactly.
    content_hashes = []
    for model, folder in zip(models, (original, repeat)):
        if model.pop('run_id') != folder.name:
            raise ValueError('Mismatched checkpoint run metadata')
        content_hashes.append(digest(canonical(model)))
    checks = {
        'model_content_except_run_id': content_hashes[0] == content_hashes[1],
        'loss_curve_bytes': (original / 'loss.json').read_bytes() == (repeat / 'loss.json').read_bytes(),
        'training_config_bytes': (original / 'config.json').read_bytes() == (repeat / 'config.json').read_bytes(),
        'metrics': first['metrics'] == run['metrics'],
        'same_trainer': first['trainer_sha256'] == run['trainer_sha256'],
        'same_corpus': first['dataset_sha256'] == run['dataset_sha256'],
        'deployment_is_original': digest(deployed.read_bytes()) == first['model_sha256']}
    receipt = {'checked_at': utc_now(), 'original_run': original.name, 'repeat_run': repeat.name,
               'optimizer_updates': 300, 'corpus_sha256': run['dataset_sha256'],
               'trainer_sha256': run['trainer_sha256'], 'original_artifact_sha256': first['model_sha256'],
               'repeat_artifact_sha256': run['model_sha256'], 'model_content_sha256': content_hashes,
               'loss_sha256': digest((repeat / 'loss.json').read_bytes()), 'passed': all(checks.values()),
               'checks': checks, 'slm_weights_updated': False,
               'scope': 'Repeated local CPU training on the same numeric data. Artifact bytes include a fresh run ID.'}
    dump_json(output, receipt)
    print(json.dumps({'output': str(output), 'passed': receipt['passed'], 'checks': checks}))
    return receipt['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/local/ranker-reproduction.json')
    raise SystemExit(0 if reproduce(parser.parse_args().output) else 1)
