"""Bounded PyInstaller/pycdc adapters; no sample import, exec, eval or run."""
import hashlib
import json
from pathlib import Path
import sys
import uuid
from .runner import bounded_process


class PythonTools:
    def __init__(self, config):
        self.config = config
        self.root = Path(config['evidence_dir'])
        self.extractions = {}

    def unpack(self, data, sample):
        digest = hashlib.sha256(data).hexdigest()
        base = self.root / 'python' / uuid.uuid4().hex
        base.mkdir(parents=True)
        snapshot = base / 'input.bin'
        snapshot.write_bytes(data)
        argv = [sys.executable, '-m', 'vm_tools.unpack_worker', self.config['pyinstxtractor'],
                str(snapshot.resolve()), str((base / 'entries').resolve())]
        raw = bounded_process(argv, self.root / 'work', memory_limit=True)
        result = json.loads(raw)
        self.extractions[digest] = (base / 'entries', result['entries'])
        return raw, 'pyinstxtractor/815d31cf+bounded-entry-adapter', [result['coverage'],
            'Entry scripts extracted; no bytecode executed; decoder support is checked separately']

    def entry_path(self, data, entry_index):
        digest = hashlib.sha256(data).hexdigest()
        if digest not in self.extractions:
            raise ValueError('Run unpack_pyinstaller on this sample first')
        folder, entries = self.extractions[digest]
        entry = next((e for e in entries if e['entry_index'] == entry_index), None)
        if entry is None:
            raise ValueError('Entry index is not in this sample extraction')
        path = (folder / entry['artifact']).resolve()
        if path.parent != folder.resolve() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError('Extracted artifact provenance changed')
        return path

    def decompile(self, data, entry_index):
        path = self.entry_path(data, entry_index)
        raw = bounded_process([self.config['pycdc'], str(path)], self.root / 'work',
                              strict_stderr=True, memory_limit=True)
        if not raw.strip() or any(word in raw for word in ('Unsupported opcode', 'Decompyle incomplete', 'Decompyle Error')):
            raise RuntimeError('pycdc did not produce a complete decompilation')
        return raw, 'pycdc/b4289760', ['Static bytecode decompilation; not all Python versions/opcodes are supported']

    def disassemble(self, data, entry_index):
        path = self.entry_path(data, entry_index)
        raw = bounded_process([self.config['pycdas'], str(path)], self.root / 'work',
                              strict_stderr=True, memory_limit=True)
        if not raw.strip() or 'UNKNOWN' in raw or 'Unsupported opcode' in raw:
            raise RuntimeError('pycdas returned empty or unsupported bytecode output')
        return raw, 'pycdas/b4289760', [
            'BYTECODE DISASSEMBLY ONLY: Python source was not recovered completely',
            'Names/constants/opcodes are static evidence; encrypted payloads and runtime behavior remain unresolved']
