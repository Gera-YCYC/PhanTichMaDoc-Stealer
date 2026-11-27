"""Small real-SLM regression check; not a malware quality benchmark."""
import json
from pathlib import Path
import sys
import uuid
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stealer_agent.journal import Journal, dump_json
from stealer_agent.reviewer import review_report
from stealer_agent.transport import OllamaClient

root = Path(__file__).resolve().parents[1]
config = json.loads((root / 'config/host.example.json').read_text())
report = {'verdict':'inconclusive', 'verdict_claim_ids':[], 'rejected_claims':[], 'validation_notes':[], 'claims':[
    {'id':'C1','text':'The file is a .NET PE.', 'evidence':[{'quote':'"format": "PE .NET"'}]},
    {'id':'C2','text':'The file is benign and a .NET program.', 'evidence':[{'quote':'"name": ".text"'}]},
    {'id':'C3','text':'The file is a PyInstaller application.', 'evidence':[{'quote':'No IOC candidates found'}]},
]}
journal = Journal(root / 'runs' / ('reviewer_' + uuid.uuid4().hex[:12]))
llm = OllamaClient(config)
journal.append('model_metadata', model=llm.inspect())
checked, metrics = review_report(report, llm, journal)
result = {'kind':'real-model-semantic-regression-not-coursework-score', 'run_directory':str(journal.directory),
          'expected_kept':['C1'], 'actual_kept':[c['id'] for c in checked['claims']],
          'result':checked, 'metrics':metrics}
result['passed'] = result['actual_kept'] == result['expected_kept']
dump_json(journal.directory / 'result.json', result)
print(json.dumps({k: result[k] for k in ('passed','actual_kept','run_directory')}))
