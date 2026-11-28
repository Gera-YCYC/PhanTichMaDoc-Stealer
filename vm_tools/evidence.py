"""Immutable feature records retained inside the VM, with bounded line pages."""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from stealer_agent.journal import canonical, dump_json, utc_now
from .code_search import load_model, navigation_pages, select_contexts


class EvidenceStore:
    def __init__(self, directory: Path, page_chars: int = 3500):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.page_chars = page_chars
        self.records: dict[str, dict] = {}
        self.page_hints: dict[str, list] = {}

    def add(self, *, sample: str, sample_sha256: str, tool: str, backend: str,
            text: str, status: str = "ok", duration_s: float = 0, limitations=None) -> dict:
        eid = "ev_" + uuid.uuid4().hex[:16]
        # Split oversized source lines rather than silently losing their tails.
        lines = []
        for source_line, original in enumerate(text.splitlines(), 1):
            for start in range(0, max(1, len(original)), 600):
                lines.append({"line": len(lines) + 1, "source_line": source_line,
                              "text": original[start:start + 600]})
        if len(lines) > 16000:
            raise ValueError("Evidence exceeds line-count bound")
        record = {"evidence_id": eid, "sample": sample, "sample_sha256": sample_sha256,
                  "tool": tool, "backend": backend, "status": status,
                  "timestamp": utc_now(), "duration_s": round(duration_s, 4),
                  "limitations": limitations or [], "lines": lines,
                  "output_sha256": hashlib.sha256(canonical(lines)).hexdigest()}
        self.records[eid] = record
        dump_json(self.directory / f"{eid}.json", record)
        return self.page(eid, 0)

    def get(self, eid: str, sample_sha256: str) -> dict:
        record = self.records.get(eid)
        if record is None or record["sample_sha256"] != sample_sha256:
            raise ValueError("Evidence ID not found in this VM session or sample mismatch")
        return record

    def _pages(self, record):
        pages, current, count = [], [], 0
        for line in record["lines"]:
            size = len(line["text"]) + 50
            if current and count + size > self.page_chars:
                pages.append(current)
                current, count = [], 0
            current.append(line)
            count += size
        if current or not pages:
            pages.append(current)
        return pages

    def page(self, eid: str, page: int) -> dict:
        record = self.records[eid]
        pages = self._pages(record)
        if type(page) is not int or not 0 <= page < len(pages):
            raise ValueError("Evidence page out of range")
        result = {k: v for k, v in record.items() if k != "lines"}
        result.update(lines=pages[page], page=page, page_count=len(pages),
                      total_lines=len(record["lines"]), truncated=len(pages) > 1)
        for hint in self.page_hints.get(eid, []):
            if hint['page'] == page:
                result['navigation_anchor'] = hint['anchor']
                break
        return result

    def search(self, eid: str, digest: str, query: str, *, occurrence_order=False) -> dict:
        record = self.get(eid, digest)
        code = record['tool'] in {'decompile_dotnet','decompile_python','disassemble_python','python_ast','decode_python_literals'}
        model = load_model() if code and not occurrence_order else None
        selected, groups, hit_count = select_contexts(record, query, model, max_contexts=2)
        result = {k: v for k, v in record.items() if k != 'lines'}
        if code and not hit_count:
            if eid not in self.page_hints:
                self.page_hints[eid] = navigation_pages(self._pages(record))
            result['navigation_pages'] = self.page_hints[eid]
        result.update(lines=selected, search_query=query, hit_count=hit_count,
                      search_groups=groups, retrieval_model_sha256=model['sha256'] if model else None,
                      retrieval_scope='learned structural relevance only; not proof of behavior or verdict' if model else 'literal occurrence order',
                      total_lines=len(record['lines']), search_truncated=hit_count>len(groups))
        return result
