"""Compile and test exactly the supplied rule, never approximate with regex."""
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
from .runner import bounded_process


def test_rule(config, source, corpus):
    if re.search(r'(?m)^\s*(?:import|include)\s', source):
        raise ValueError('YARA imports/includes are disabled for generated rules')
    if len(source) > 6000:
        raise ValueError('Rule too large')
    manifest = Path(config['yara_manifest']).resolve()
    # Corpus entries and labels belong to trusted lab configuration, not LLM args.
    task = Path(config['evidence_dir']) / 'yara' / uuid.uuid4().hex
    task.mkdir(parents=True)
    rule = task / 'generated.yar'
    rule.write_text(source, encoding='utf-8')
    result = bounded_process([sys.executable, '-m', 'vm_tools.yara_worker', str(rule.resolve()),
                              str(manifest), corpus, str(Path(config['sample_dir']).resolve())],
                             Path(config['evidence_dir']) / 'work', timeout=60, memory_limit=True)
    return result, 'yara-python/4.5.4', ['Metrics apply only to the named corpus, not all malware']
