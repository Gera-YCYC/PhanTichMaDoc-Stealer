"""Real backend smoke tests. These calls are not attributed to the agent."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stealer_agent.transport import ToolClient

root = Path(__file__).resolve().parents[1]
config = json.loads((root / 'config/host.example.json').read_text())
client = ToolClient(config, (root / 'config/lab.token').read_text().strip())
health = client.inspect()
result = {'kind': 'direct-backend-smoke-not-agent-run', 'health': health, 'samples': []}
for sample in ('safe_bundle.bin', 'public_luna.bin'):
    item = {'sample': sample, 'checks': []}
    for tool in ('identify', 'unpack_pyinstaller'):
        response = client.call(tool, {'sample': sample})
        item['checks'].append({k: response.get(k) for k in ('tool', 'status', 'backend', 'sample_sha256', 'total_lines', 'limitations')})
        if tool == 'unpack_pyinstaller' and response['status'] == 'ok':
            inventory = json.loads(''.join(r['text'] for r in response['lines']))
            item['inventory'] = inventory
            main_entries = [e for e in inventory['entries'] if e['application_entry']]
            for entry in main_entries:
                decoded = client.call('decompile_python', {'sample': sample, 'entry_index': entry['entry_index']})
                check = {k: decoded.get(k) for k in ('tool', 'status', 'backend', 'total_lines', 'limitations')}
                if decoded['status'] != 'ok':
                    check['error'] = ''.join(r['text'] for r in decoded['lines'])[:500]
                item['checks'].append(check)
        elif response['status'] != 'ok':
            item['checks'][-1]['error'] = ''.join(r['text'] for r in response['lines'])[:500]
    result['samples'].append(item)
(root / 'evidence/local/python-backend-probes.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result['samples'], indent=2))
