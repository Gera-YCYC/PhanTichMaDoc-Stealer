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
    parser.add_argument("--with-yara", action="store_true", help="Rescan the registered sample with the frozen project rules after analysis")
    parser.add_argument("--measure-resources", action="store_true", help="Sample host-wide available RAM and NVIDIA memory during each analysis run")
    args = parser.parse_args()
    if args.with_yara and not args.public_demo:
        parser.error('--with-yara requires --public-demo and a registered corpus')
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
        vm = ToolClient(config, token)
        agent = Agent(config, OllamaClient(config), vm)
        if args.measure_resources:
            from hashlib import sha256
            from .journal import dump_json, verify_journal
            from .resource_window import ResourceWindow
            with ResourceWindow() as observer:
                result = agent.run(args.sample)
            directory = Path(result['run_directory'])
            journal_path = directory / 'events.jsonl'
            verify_journal(journal_path)
            dump_json(directory / 'host-resources.json', {
                'run_id': result['run_id'], 'journal_sha256': sha256(journal_path.read_bytes()).hexdigest(),
                'sample_sha256': result['sample_sha256'], 'model_digest': result['model'].get('digest'),
                'measurements': observer.metrics})
        else:
            result = agent.run(args.sample)
        print(json.dumps({k: result[k] for k in ("run_id", "status", "successful_tools", "acceptance", "run_directory")}, ensure_ascii=False, indent=2))
        if result["status"] == "incomplete":
            code = 2
        elif args.with_yara:
            from .yara_case import scan_case
            output = scan_case(Path(result['run_directory']), vm)
            print('YARA: ' + str(output / 'ket-qua.md'))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
