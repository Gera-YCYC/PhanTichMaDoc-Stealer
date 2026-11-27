"""Real VM backend smoke; explicitly distinct from an SLM-selected tool run."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.transport import ToolClient
from stealer_agent.journal import dump_json, utc_now
from scripts.sync_vm import SSH, DEST


def main():
    cfg = json.loads((ROOT/'config/host.example.json').read_text())
    client = ToolClient(cfg, (ROOT/'config/lab.token').read_text().strip())
    health = client.inspect()
    sample = 'public_gomorrah.bin'
    expected = json.loads((ROOT/'config/public-samples.json').read_text())['samples'][sample]['sha256']
    checks = []
    for action in ('detect_it_easy', 'floss'):
        result = client.call(action, {'sample': sample})
        check = {k: result.get(k) for k in ('tool','backend','status','sample_sha256','output_sha256',
                                           'evidence_id','total_lines','duration_s','limitations')}
        check['sample_hash_matches'] = result.get('sample_sha256') == expected
        check['first_page'] = result.get('lines', [])
        checks.append(check)
        print(json.dumps({k:v for k,v in check.items() if k != 'first_page'}), flush=True)
    guest_check = """import json,stat
from pathlib import Path
r=Path('/opt/stealer-lab')
paths=[p for d in ('stealer_agent','vm_tools') for p in (r/d).rglob('*') if p.is_file()]
bad=[str(p.relative_to(r)) for p in paths if p.stat().st_uid!=0 or p.stat().st_mode & 0o022]
print(json.dumps({'source_files':len(paths),'unsafe_source_permissions':bad}))
"""
    permissions = json.loads(subprocess.check_output(['ssh',*SSH,DEST,'sudo python3 -'],
                            input=guest_check.encode(), timeout=30))
    passed = all(c['status']=='ok' and c['sample_hash_matches'] for c in checks) and not permissions['unsafe_source_permissions']
    receipt = {'created_at':utc_now(),'kind':'direct-real-backend-not-agent-run','passed':passed,
               'health_tools':health['tools'],'isolation':health['isolation'],
               'checks':checks,'permissions':permissions,
               'verifier_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    dump_json(ROOT/'evidence/local/die-floss-smoke.json',receipt)
    return 0 if passed else 2


if __name__ == '__main__':
    raise SystemExit(main())
