"""Bounded readiness wait after starting the VM and local model; no sample is analyzed."""
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stealer_agent.transport import OllamaClient, ToolClient

ROOT=Path(__file__).resolve().parents[1]
cfg=json.loads((ROOT/'config/host.example.json').read_text())
cfg['timeout_s']=3
token=(ROOT/'config/lab.token').read_text().strip()
deadline=time.monotonic()+45
error=None
while time.monotonic()<deadline:
    try:
        model=OllamaClient(cfg).inspect()
        ToolClient(cfg,token).inspect()
        print('READY: local '+model['tag']+' and isolated VM tools')
        break
    except Exception as exc:
        error=type(exc).__name__
        time.sleep(1)
else:
    raise SystemExit('Lab not ready after 45 seconds ('+str(error)+'). Inspect model/service logs; no sample was run.')
