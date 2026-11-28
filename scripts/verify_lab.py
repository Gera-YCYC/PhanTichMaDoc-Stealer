"""Read-only inventory with source/dataset hashes. Never reads key contents to output."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stealer_agent.journal import dump_json, utc_now
from stealer_agent.transport import OllamaClient, ToolClient
from scripts.sync_vm import SSH, DEST

ROOT = Path(__file__).resolve().parents[1]
GUEST_CHECK = '''import hashlib,json,subprocess
from pathlib import Path
r=Path('/opt/stealer-lab')
c=json.loads((r/'config/vm.json').read_text())
source={str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('stealer_agent','vm_tools') for p in sorted([*(r/d).glob('*.py'),*(r/d).glob('code_ranker.json')])}
samples=[{'sample':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size_bytes':p.stat().st_size,'mode':oct(p.stat().st_mode & 0o777)} for p in sorted((r/'samples').iterdir()) if p.is_file()]
tools={name:{'path':c.get(name),'sha256':hashlib.sha256(Path(c[name]).read_bytes()).hexdigest()} for name in ('ilspycmd','pycdc','pycdas','pyinstxtractor') if name in c}
print(json.dumps({'source':source,'samples':samples,'tools':tools,'default_routes':subprocess.check_output(['ip','route','show','default'],text=True).strip(),'config':c}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('config/host.example.json'))
    args = parser.parse_args()
    cfg = json.loads((ROOT/args.config).read_text(encoding='utf-8-sig'))
    client = ToolClient(cfg, (ROOT/'config/lab.token').read_text().strip())
    guest = json.loads(subprocess.check_output(['ssh',*SSH,DEST,'sudo python3 -'],input=GUEST_CHECK.encode(),timeout=30))
    expected = {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                for d in ('stealer_agent','vm_tools') for p in sorted([*(ROOT/d).glob('*.py'),*(ROOT/d).glob('code_ranker.json')])}
    model = OllamaClient(cfg).inspect()
    allowed = ('ethernet0.connectionType','ethernet0.vnet','isolation.tools.copy.disable',
               'isolation.tools.paste.disable','isolation.tools.dnd.disable','sharedFolder.maxNum')
    vmx = (ROOT/'private/lab-vm/StealerLab.vmx').read_text()
    vm_settings = [line for line in vmx.splitlines() if line.startswith(allowed)]
    vmrun = r'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    snapshot_list = subprocess.check_output([vmrun,'listSnapshots',str(ROOT/'private/lab-vm/StealerLab.vmx')],text=True)
    result = {'created_at':utc_now(),'kind':'read-only-live-lab-verification','health':client.inspect(),
              'model':model,'vm':guest,'host_source':expected,'source_matches_vm':expected==guest['source'],
              'vmx_isolation_settings':vm_settings,'snapshots':snapshot_list.splitlines(),
              'old_model_on_D_preserved':Path(r'D:\Mountain-Market-Data\ollama-models').is_dir()}
    dump_json(ROOT/'evidence/local/lab-verification.json',result)
    print(json.dumps({'source_matches_vm':result['source_matches_vm'],'sample_count':len(guest['samples']),
                     'default_routes':guest['default_routes'],'model':model['tag'],'snapshot_lines':result['snapshots']}))
    return 0 if result['source_matches_vm'] and not guest['default_routes'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
