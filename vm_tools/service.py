"""VM dispatcher. The model supplies names and evidence IDs, never shell/path strings."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path

from stealer_agent.contracts import validate_action, TOOLS
from stealer_agent.security import contained_file
from . import analyzers
from .evidence import EvidenceStore
from .runner import bounded_process
from .python_tools import PythonTools
from .string_extractor import BACKEND as STRINGS_BACKEND
from .native_tools import NativeTools


class ToolService:
    def __init__(self, config: dict):
        self.config = config
        self.root = Path(config["sample_dir"])
        self.store = EvidenceStore(Path(config["evidence_dir"]), config.get("page_chars", 3500))
        self.python = PythonTools(config)
        self.native = NativeTools(config)

    def capabilities(self) -> dict:
        from .yara_tools import profile_info
        return {"detect_it_easy": {"available": self.native.available('diec'), "backend": "diec"},
                "floss": {"available": self.native.available('floss'), "backend": "floss"},
                "unpack_pyinstaller": {"available": Path(self.config.get("pyinstxtractor", "")).is_file(), "backend": "pyinstxtractor"},
                "decompile_python": {"available": Path(self.config.get("pycdc", "")).is_file(), "backend": "pycdc"},
                "disassemble_python": {"available": Path(self.config.get("pycdas", "")).is_file(), "backend": "pycdas"},
                "decode_python_literals": {"available": importlib.util.find_spec('cryptography') is not None, "backend": "bounded-literal-decoder/1"},
                "test_yara": {"available": importlib.util.find_spec("yara") is not None, "backend": "yara-python", "profiles": profile_info(self.config)},
                "yara_candidates": {"available": True, "backend": "raw-yara-candidates/2"},
                "identify": {"available": importlib.util.find_spec("pefile") is not None, "backend": "pefile"},
                "decompile_dotnet": {"available": Path(self.config["ilspycmd"]).is_file(), "backend": "ilspycmd"},
                "strings": {"available": True, "backend": STRINGS_BACKEND},
                "python_ast": {"available": True, "backend": "python-ast/1"},
                "extract_ioc": {"available": True, "backend": "ioc-regex/1"},
                "read_evidence": {"available": True, "backend": "feature-store"},
                "search_evidence": {"available": True, "backend": "feature-store-literal-search"}}


    def call(self, action: str, arguments: dict) -> dict:
        validate_action({"action": action, "arguments": arguments, "reason": "VM dispatch validation", "report": None})
        if action not in TOOLS:
            raise ValueError("Unknown tool")
        sample = arguments["sample"]
        path = contained_file(self.root, sample, self.config.get("max_sample_bytes", 16_777_216))
        with path.open('rb') as handle:
            data = handle.read(self.config.get("max_sample_bytes", 16_777_216) + 1)
        if len(data) > self.config.get("max_sample_bytes", 16_777_216):
            raise ValueError('Sample grew beyond size limit')
        digest = hashlib.sha256(data).hexdigest()
        started = time.perf_counter()
        backend, limits = "unavailable", []
        try:
            if action == "read_evidence":
                eid = arguments["evidence_id"]
                record = self.store.get(eid, digest)
                if "field_call_line" in arguments:
                    if record["tool"] != "decompile_dotnet" or record["status"] != "ok":
                        raise ValueError("Field navigation requires successful ILSpy evidence")
                    root = Path(self.config["evidence_dir"])
                    result = json.loads(bounded_process(
                        [sys.executable, "-m", "vm_tools.field_call", str((root / (eid + ".json")).resolve()),
                         str(arguments["field_call_line"])], root / "work", timeout=20, max_bytes=32_000,
                        strict_stderr=True, memory_limit=True,
                        env_overrides={"PYTHONPATH": str(Path(__file__).resolve().parents[1]) +
                                       os.pathsep + os.environ.get("PYTHONPATH", "")}))
                    if any(r != record["lines"][r["line"] - 1] for r in result["lines"]):
                        raise ValueError("Field navigation returned different source rows")
                    return {**{k: record[k] for k in ("sample", "sample_sha256", "output_sha256", "evidence_id", "tool")},
                            "status": "ok", "navigation": result["status"], "ranges": result["ranges"],
                            "requested_line": result["line"], "lines": result["lines"]}
                return self.store.page(arguments["evidence_id"], arguments.get("page", 0))
            if action == "search_evidence":
                result = self.store.search(arguments['evidence_id'], digest, arguments['query'],
                                           occurrence_order=arguments.get('occurrence_order',False))
                if result['tool'] in {'decompile_dotnet', 'decompile_python', 'decode_python_literals'} and result['search_groups']:
                    try:
                        folder = Path(self.config['evidence_dir']) / 'context-inputs'
                        folder.mkdir(parents=True, exist_ok=True)
                        snapshot = folder / (uuid.uuid4().hex + '.json')
                        snapshot.write_text(json.dumps({'record': self.store.get(arguments['evidence_id'], digest),
                            'anchors': [g['anchor_line'] for g in result['search_groups']],
                            'verify_staging': arguments.get('verify_staging', False),
                            'visible_lines': [r['line'] for r in result['lines']]}), encoding='utf-8')
                        context = json.loads(bounded_process([sys.executable, '-m', 'vm_tools.context_worker', str(snapshot.resolve())],
                            Path(self.config['evidence_dir'])/'work', timeout=20, max_bytes=100_000,
                            strict_stderr=True, memory_limit=True,
                            env_overrides={'PYTHONPATH': str(Path(__file__).resolve().parents[1]) +
                                os.pathsep + os.environ.get('PYTHONPATH', '')}))
                        lines = {r['line']: r for r in result['lines']}
                        lines.update({r['line']: r for r in context['lines']})
                        result.update(lines=[lines[n] for n in sorted(lines)], context_links=context['context_links'],
                                      syntax_context=context['syntax_context'])
                        result.update({k:context[k] for k in ('operation_facts','operation_backend','operation_status') if k in context})
                        if 'archive_link' in context:
                            result['archive_link']=context['archive_link']
                        if 'staging_link' in context:
                            result['staging_link']=context['staging_link']
                    except Exception as exc:
                        result['syntax_context'] = {'status': 'unavailable', 'error_class': type(exc).__name__,
                                                   'scope': 'Literal search remains available; no syntax links claimed'}
                return result
            if action == "identify":
                text, backend, limits = analyzers.identify(data, sample)
            elif action == "unpack_pyinstaller":
                text, backend, limits = self.python.unpack(data, sample)
            elif action == "decompile_python":
                text, backend, limits = self.python.decompile(data, arguments['entry_index'])
            elif action == "disassemble_python":
                text, backend, limits = self.python.disassemble(data, arguments['entry_index'])
            elif action == 'decode_python_literals':
                record = self.store.get(arguments['evidence_id'], digest)
                if record['tool'] not in ('disassemble_python','decompile_python') or record['status']!='ok':
                    raise ValueError('Decoder requires successful Python source/disassembly evidence')
                backend='bounded-literal-decoder/1'
                folder=Path(self.config['evidence_dir'])/'decode-inputs'
                folder.mkdir(parents=True,exist_ok=True)
                snapshot=folder/(uuid.uuid4().hex+'.json')
                snapshot.write_text(json.dumps(record),encoding='utf-8')
                text=bounded_process([sys.executable,'-m','vm_tools.decode_worker',str(snapshot.resolve())],
                    Path(self.config['evidence_dir'])/'work',timeout=35,max_bytes=1_100_000,
                    memory_limit=True,strict_stderr=True)
                limits=['Literal transforms only: base64, Fernet with embedded constant key, bounded zlib, UTF-8.',
                        'No sample import/eval/exec; recovered candidate source does not prove runtime reachability.']
            elif action == "test_yara":
                from .yara_tools import test_rule
                text, backend, limits = test_rule(self.config, arguments['rule'], arguments['corpus'], arguments.get('profile', 'fixture'))
            elif action == 'yara_candidates':
                from .yara_candidates import extract
                text = json.dumps(extract(data))
                backend = 'raw-yara-candidates/2'
                limits = ['Candidate literals occur in original bytes; presence alone does not prove malicious behavior.',
                          'Bounded ASCII and ASCII-range UTF-16LE only; compressed payload strings may be unavailable.']
            elif action == "strings":
                text, backend, limits = analyzers.strings(data)
            elif action == 'detect_it_easy':
                backend = 'diec/'+self.config.get('diec_version','unknown')
                text, backend, limits = self.native.analyze('diec', data, sample)
            elif action == 'floss':
                backend = 'floss/'+self.config.get('floss_version','unknown')
                info = json.loads(analyzers.identify(data, sample)[0])
                if not info['format'].startswith('PE'):
                    raise ValueError('FLOSS adapter requires a PE sample')
                text, backend, limits = self.native.analyze('floss', data, sample, is_dotnet=info['is_dotnet'])
            elif action == "python_ast":
                if path.suffix.lower() != ".py":
                    raise ValueError("python_ast supports source .py only; bytecode must be decompiled in a later adapter")
                text, backend, limits = analyzers.python_ast(data)
            elif action == "extract_ioc":
                record = self.store.get(arguments["evidence_id"], digest)
                if record["status"] != "ok":
                    raise ValueError("Cannot extract IOC from failed analysis")
                text, backend, limits = analyzers.extract_ioc(record)
            elif action == "decompile_dotnet":
                info, _, _ = analyzers.identify(data, sample)
                if not json.loads(info)["is_dotnet"]:
                    raise ValueError("Sample is not identified as a managed PE")
                executable = Path(self.config["ilspycmd"]).resolve()
                argv = [str(executable), "--disable-updatecheck"]
                typename = arguments.get("type_name")
                if typename:
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.+`]{0,149}", typename):
                        raise ValueError("Invalid .NET type name")
                    argv.extend(["-t", typename])
                argv.append(str(path))
                backend = "ilspycmd"
                # A fixed local copy binds analysis to the hashed bytes.
                snapshot_dir = Path(self.config["evidence_dir"]) / "inputs" / digest
                snapshot_dir.mkdir(parents=True, exist_ok=True)
                snapshot = snapshot_dir / sample
                if not snapshot.exists():
                    snapshot.write_bytes(data)
                if hashlib.sha256(snapshot.read_bytes()).hexdigest() != digest:
                    raise ValueError("Immutable input snapshot changed")
                argv[-1] = str(snapshot.resolve())
                text = bounded_process(argv, Path(self.config["evidence_dir"]) / "work",
                                       timeout=self.config.get("tool_timeout_s", 90))
                if not text.strip():
                    raise RuntimeError("ILSpy returned empty output")
                limits = ["Static decompilation; runtime behavior has not been observed"]
            result = self.store.add(sample=sample, sample_sha256=digest, tool=action, backend=backend,
                                    text=text, limitations=limits, duration_s=time.perf_counter() - started)
            if action in {'decompile_dotnet', 'decompile_python', 'decode_python_literals'} and '/webhooks/' in text.casefold():
                record_path = self.store.directory / (result['evidence_id'] + '.json')
                try:
                    features = bounded_process(
                        [sys.executable, '-m', 'vm_tools.channel_shapes', str(record_path.resolve())],
                        self.store.directory / 'work', timeout=15, max_bytes=24000, memory_limit=True, strict_stderr=True,
                        env_overrides={'PYTHONPATH': str(Path(__file__).resolve().parents[1]) +
                                       os.pathsep + os.environ.get('PYTHONPATH', '')})
                    result['channel_shapes'] = json.loads(features)
                except (RuntimeError, ValueError, OSError) as exc:
                    result['channel_feature_error'] = type(exc).__name__
            return result
        except Exception as exc:
            status = "unavailable" if isinstance(exc, (ImportError, FileNotFoundError)) else "error"
            return self.store.add(sample=sample, sample_sha256=digest, tool=action, backend=backend,
                                  text=f"{type(exc).__name__}: {exc}", status=status,
                                  duration_s=time.perf_counter() - started)
