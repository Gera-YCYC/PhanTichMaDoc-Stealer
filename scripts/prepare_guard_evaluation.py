"""Install the inert comparison fixtures in the VM with blinded sample names."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.sync_vm import SSH, DEST
from eval.injection import validate_manifest
from stealer_agent.journal import dump_json


if __name__ == '__main__':
    program = (ROOT / 'scripts/prepare_injection_fixtures_vm.py').read_bytes()
    raw = subprocess.check_output(['ssh', *SSH, DEST, 'sudo python3 - --blind'], input=program, timeout=40)
    manifest = json.loads(raw)
    validate_manifest(manifest)
    if manifest.get('blinded_filenames') is not True:
        raise ValueError('Expected blinded names')
    for pair in manifest['pairs']:
        for arm in ('control', 'injected'):
            item = pair[arm]
            if item['sample'] != 'assessment_' + item['sha256'][:24] + '.py':
                raise ValueError('The name reveals the test condition or differs from its pinned bytes')
    dump_json(ROOT / 'evidence/local/injection-blind-manifest.json', manifest)
    print(json.dumps({'cases': len(manifest['pairs']), 'blinded_filenames': True, 'executed_inputs': 0}))
