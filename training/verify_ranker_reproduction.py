"""Re-train on the frozen numeric corpus and compare against the deployed ranker."""
import argparse
import ast
import hashlib
import json
import math
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import canonical, dump_json, utc_now


def digest(data):
    return hashlib.sha256(data).hexdigest()


def feature_definitions(path):
    names = {'FEATURES', 'VERSION', '_STRING', '_CALL', '_OPCODE', '_USE', '_IMPORT', '_DECL', 'structural_features'}
    result = {}
    for node in ast.parse(path.read_bytes()).body:
        if isinstance(node, ast.FunctionDef):
            key = node.name
        elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            key = node.targets[0].id
        else:
            continue
        if key in names:
            if key in result:
                raise ValueError('Feature binding was redefined: ' + key)
            result[key] = ast.dump(node, include_attributes=False)
    if set(result) != names:
        raise ValueError('Incomplete set of structural feature definitions')
    return result


def reproduce(output, portable=False):
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
    # Preserve the original exact test. On another OS, newline conventions
    # and libm can differ. Only the floating-point curve and weights get a
    # numeric tolerance. Epoch IDs, the data, training code and decisions do not.
    configs = [json.loads((p/'config.json').read_bytes()) for p in (original, repeat)]
    curves = [json.loads((p/'loss.json').read_bytes()) for p in (original, repeat)]
    weight_vectors = [m['weights'] + [m['bias']] for m in models]
    def max_error(left, right):
        if not left or len(left) != len(right) or any(not math.isfinite(v) for v in left + right):
            raise ValueError('Invalid numeric training artifact')
        return max(abs(a - b) for a, b in zip(left, right))
    loss_error = max_error(*[[v['train_binary_cross_entropy_plus_l2'] for v in curve] for curve in curves])
    weight_error = max_error(*weight_vectors)
    tolerance = 1e-12
    archived_features = ROOT/'training/corpus/feature-source-v1.txt'
    portable_checks = {
        'metadata': {k:v for k,v in models[0].items() if k not in ('weights','bias')} ==
                    {k:v for k,v in models[1].items() if k not in ('weights','bias')},
        'config_values': configs[0] == configs[1],
        'epochs': all([v['epoch'] for v in curve] == list(range(configs[0]['epochs']+1)) for curve in curves),
        'loss_within_tolerance': loss_error <= tolerance, 'weights_within_tolerance': weight_error <= tolerance,
        'archived_feature_file': digest(archived_features.read_bytes()) == first['feature_code_sha256'],
        'feature_definitions': feature_definitions(archived_features) == feature_definitions(ROOT/'vm_tools/code_search.py'),
        **{k: checks[k] for k in ('metrics','same_trainer','same_corpus','deployment_is_original')},
    }
    receipt = {'checked_at': utc_now(), 'original_run': original.name, 'repeat_run': repeat.name,
               'optimizer_updates': 300, 'corpus_sha256': run['dataset_sha256'],
               'trainer_sha256': run['trainer_sha256'], 'original_artifact_sha256': first['model_sha256'],
               'repeat_artifact_sha256': run['model_sha256'], 'model_content_sha256': content_hashes,
               'loss_sha256': digest((repeat / 'loss.json').read_bytes()),
               'passed': all(portable_checks.values()) if portable else all(checks.values()),
               'mode': 'portable' if portable else 'exact', 'platform': platform.system(),
               'python': platform.python_version(), 'exact_passed': all(checks.values()),
               'portable_checks': portable_checks, 'absolute_tolerance': tolerance,
               'maximum_loss_delta': loss_error, 'maximum_parameter_delta': weight_error,
               'feature_file_at_original_train': first['feature_code_sha256'],
               'feature_file_at_repeat': run['feature_code_sha256'],
               'checks': checks, 'slm_weights_updated': False,
               'scope': 'Repeated local CPU training on the same numeric data. Artifact bytes include a fresh run ID.'}
    dump_json(output, receipt)
    print(json.dumps({k:receipt[k] for k in ('mode','platform','python','optimizer_updates','passed','exact_passed',
                                              'maximum_loss_delta','maximum_parameter_delta','checks','portable_checks')}))
    return receipt['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/local/ranker-reproduction.json')
    parser.add_argument('--portable', action='store_true', help='Also allow platform newline and declared numeric tolerance')
    args = parser.parse_args()
    raise SystemExit(0 if reproduce(args.output, args.portable) else 1)
