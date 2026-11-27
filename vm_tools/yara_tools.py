"""Compile and test exactly the supplied rule, never approximate with regex."""
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
from .runner import bounded_process


def profile_manifest(config, profile):
    if profile == 'fixture':
        return Path(config['yara_manifest']).resolve(strict=True)
    if profile not in {'real-v1', 'real-v3'}:
        raise ValueError('Unknown YARA corpus profile')
    return Path(config['yara_profiles'][profile]).resolve(strict=True)


def profile_info(config):
    profiles = {}
    for profile in ('fixture', 'real-v1', 'real-v3'):
        try:
            manifest = json.loads(profile_manifest(config, profile).read_text(encoding='utf-8'))
            profiles[profile] = {'dataset_origin': manifest['dataset_origin'],
                'corpora_sha256': hashlib.sha256(json.dumps(manifest['corpora'], sort_keys=True,
                    separators=(',', ':')).encode()).hexdigest(),
                'counts': {name: {'positive': sum(r['positive'] is True for r in rows),
                                  'negative': sum(r['positive'] is False for r in rows)}
                           for name, rows in manifest['corpora'].items()}}
        except (KeyError, OSError, ValueError):
            continue
    return profiles


def test_rule(config, source, corpus, profile='fixture'):
    if re.search(r'(?m)^\s*(?:import|include)\s', source):
        raise ValueError('YARA imports/includes are disabled for generated rules')
    if len(source) > 6000:
        raise ValueError('Rule too large')
    manifest = profile_manifest(config, profile)
    # Corpus entries and labels belong to trusted lab configuration, not LLM args.
    task = Path(config['evidence_dir']) / 'yara' / uuid.uuid4().hex
    task.mkdir(parents=True)
    rule = task / 'generated.yar'
    rule.write_text(source, encoding='utf-8')
    result = bounded_process([sys.executable, '-m', 'vm_tools.yara_worker', str(rule.resolve()),
                              str(manifest), corpus, str(Path(config['sample_dir']).resolve())],
                             Path(config['evidence_dir']) / 'work', timeout=60, memory_limit=True)
    return result, 'yara-python/4.5.4', ['Metrics apply only to the named corpus, not all malware']
