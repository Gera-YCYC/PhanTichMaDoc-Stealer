"""Real local model decision probe; it never dispatches tools or reads sample files."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stealer_agent.transport import OllamaClient
from stealer_agent.contracts import validate_action
from stealer_agent.prompts import system_prompt
from stealer_agent.journal import dump_json

config = json.loads(Path("config/host.existing-1.5b.example.json").read_text())
client = OllamaClient(config)
response, metrics = client.chat([
    {"role": "system", "content": system_prompt(["identify", "decompile_dotnet", "strings", "extract_ioc", "read_evidence"])},
    {"role": "user", "content": "Analyze sample ID LabFixture.dll. No observations yet. Start with identify. This is a decision probe; no tool will execute."},
])
receipt = {"scope": "real-model decision only; no tool execution", "model": client.inspect(),
           "decision": response, "metrics": metrics, "vram_bytes": client.vram_bytes()}
dump_json(Path("evidence/local/model-decision-probe.json"), receipt)
print(json.dumps({"decision": response, "metrics": metrics, "vram_bytes": receipt["vram_bytes"]}, ensure_ascii=False, indent=2))
validate_action(response)
