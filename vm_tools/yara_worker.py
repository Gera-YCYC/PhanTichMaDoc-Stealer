"""Dedicated bounded process for YARA compilation/scanning; never executes inputs."""
import hashlib
import json
from pathlib import Path
import sys
import yara
from stealer_agent.security import contained_file


def evaluate(rule_file, manifest_file, corpus, sample_root):
    manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
    cases = manifest['corpora'][corpus]
    if not cases or len(cases) > 200:
        raise ValueError('Corpus must have 1-200 explicit samples')
    rule_text = rule_file.read_text(encoding='utf-8')
    compiled = yara.compile(source=rule_text, includes=False, error_on_warning=True)
    rows, identities = [], set()
    for case in cases:
        path = contained_file(sample_root, case['sample'], 32_000_000)
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != case['sha256'] or digest in identities or type(case['positive']) is not bool:
            raise ValueError('Corpus hash/label/uniqueness mismatch')
        identities.add(digest)
        matches = compiled.match(data=data, timeout=3)
        rows.append({'sample': case['sample'], 'sha256': digest, 'positive': case['positive'],
                     'matched': bool(matches), 'rules': [str(m) for m in matches]})
    positives = sum(r['positive'] for r in rows)
    negatives = len(rows) - positives
    return {'rule_sha256': hashlib.sha256(rule_text.encode()).hexdigest(), 'yara_version': yara.__version__,
            'corpus': corpus, 'dataset_origin': manifest['dataset_origin'], 'results': rows,
            'tpr': sum(r['positive'] and r['matched'] for r in rows) / positives if positives else None,
            'fpr': sum(not r['positive'] and r['matched'] for r in rows) / negatives if negatives else None,
            'positive_count': positives, 'negative_count': negatives}


if __name__ == '__main__':
    print(json.dumps(evaluate(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))))
