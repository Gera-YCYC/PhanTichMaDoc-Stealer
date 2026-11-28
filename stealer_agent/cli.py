"""Host entrypoint: only orchestrates remote VM tools and loopback Ollama."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path

from .engine import Agent
from .transport import OllamaClient, ToolClient


def main() -> int:
    parser = argparse.ArgumentParser(description="ReAct stealer analysis, local SLM + isolated VM tools")
    parser.add_argument("--config", default="config/host.example.json")
    parser.add_argument("--sample", required=True, help="Filename/sample ID in VM, never a host path")
    parser.add_argument("--runs", type=int, default=1, choices=(1, 3))
    parser.add_argument("--public-demo", action="store_true", help="Require an exact public sample hash and a >=7B local model")
    parser.add_argument("--live", action="store_true", help="Print tool dispatch/status without raw sample strings or secrets")
    parser.add_argument("--occurrence-order", action="store_true", help="Use source order in VM code searches for a ranker ablation")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8-sig"))
    config['live_progress'] = args.live
    if args.occurrence_order:
        config['occurrence_order'] = True
    if args.public_demo:
        manifest_path=Path(__file__).resolve().parents[1]/'config/public-samples.json'
        manifest=json.loads(manifest_path.read_text(encoding='utf-8'))
        if args.sample not in manifest['samples']:
            parser.error('Public demo requires a sample in config/public-samples.json; fixtures are not accepted')
        config['expected_sample_sha256']=manifest['samples'][args.sample]['sha256']
        config['require_course_model']=True
        config['evidence_kind']='real-public-malware-local-slm-vm'
    token = os.environ.get(config.get("token_env", "STEALER_LAB_TOKEN"), "")
    code = 0
    for _ in range(args.runs):
        result = Agent(config, OllamaClient(config), ToolClient(config, token)).run(args.sample)
        print(json.dumps({k: result[k] for k in ("run_id", "status", "successful_tools", "acceptance", "run_directory")}, ensure_ascii=False, indent=2))
        if result["status"] == "incomplete":
            code = 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
