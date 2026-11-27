"""Sequential real-model/VM evidence collection. Does not grade malware accuracy."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stealer_agent.engine import Agent
from stealer_agent.journal import dump_json, utc_now, verify_journal
from stealer_agent.transport import OllamaClient, ToolClient

root = Path(__file__).resolve().parents[1]
config = json.loads((root / 'config/host.example.json').read_text())
client = ToolClient(config, (root / 'config/lab.token').read_text().strip())
result = {'created_at':utc_now(), 'scope':'M4 technical integration, not independent quality evaluation', 'runs':[]}
for sample in ('LabFixture.dll', 'safe_bundle.bin', 'public_gomorrah.bin', 'public_python2024.bin'):
    run = Agent(config, OllamaClient(config), client).run(sample)
    record = {k:run[k] for k in ('run_id','sample','sample_sha256','status','successful_tools','metrics','acceptance')}
    record['journal_events_verified'] = verify_journal(Path(run['run_directory']) / 'events.jsonl')
    record['accepted_claims'] = len(run['analysis']['claims'])
    record['rejected_claims'] = len(run['analysis']['rejected_claims'])
    record['verdict'] = run['analysis']['verdict']
    result['runs'].append(record)
    dump_json(root / 'evidence/local/milestone4-latest.json', result)
    print(json.dumps(record, ensure_ascii=False), flush=True)
