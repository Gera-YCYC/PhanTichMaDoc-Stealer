"""A bounded, credential-reduced evidence view for local model requests.

Original VM output and raw journal observations stay immutable/private. Quotes in
the model view retain line coordinates, but are explicitly NOT original bytes.
Detection is heuristic: this is not a public-export approval or a DLP guarantee.
"""
from __future__ import annotations

import copy
import ast
import hashlib
import re

from .journal import canonical
from .redaction import collect_literals, EMAIL, ASSIGNMENT, LOGIN, string_values
from .security import SECRET

VERSION = 'model-evidence-projection/1'


class ModelEvidenceView:
    def __init__(self):
        self._labels = {}
        self.scan_truncated = False

    def learn(self, observation):
        texts = [r['text'] for r in observation.get('lines', [])]
        # Join only consecutive fragments of the same physical source line.
        # This catches an assignment split at EvidenceStore's 600-char boundary.
        joined, previous = [], None
        for row in observation.get('lines', []):
            if previous and row.get('source_line') is not None and row.get('source_line') == previous.get('source_line') and row['line'] == previous['line']+1:
                joined[-1] += row['text']
            else:
                joined.append(row['text'])
            previous = row
        values, truncated = collect_literals(joined)
        self.scan_truncated |= truncated
        for text in texts:
            values.update(m[0] for m in EMAIL.finditer(text))
            values.update(m[0] for m in SECRET.finditer(text))
        for value in sorted(values):
            if value not in self._labels and '__PRIVATE_LITERAL_' not in value:
                self._labels[value] = f'__PRIVATE_LITERAL_{len(self._labels)+1}__'
        # Preserve detection across escaped source spellings, without executing
        # a source expression or converting the evidence into code.
        for text in joined:
            literals = [m[2] for m in ASSIGNMENT.finditer(text)]
            literals += [literal for m in LOGIN.finditer(text) for literal in (m[1], m[2])]
            for literal in literals:
                if len(literal) > 8192:
                    continue
                try:
                    value = ast.literal_eval(literal)
                except (ValueError, SyntaxError):
                    continue
                if isinstance(value, str) and value in self._labels:
                    self._labels[literal[1:-1]] = self._labels[value]
        if len(self._labels) > 1024 or sum(map(len, self._labels)) > 1_000_000:
            raise ValueError('Credential projection bound exceeded; inference refused')

    def text(self, text):
        # Replace the whole matched span atomically: inserted labels must not be
        # scanned/replaced again by a later (possibly very short) secret.
        if not self._labels:
            return text
        pattern = '|'.join(re.escape(v) for v in sorted(self._labels, key=len, reverse=True))
        def replacement(match):
            value = match[0]
            # A one-character password must not destroy identifiers such as
            # 'data'. Whole-word occurrences are hidden; substrings are a limit.
            if len(value) < 4:
                before = text[match.start()-1:match.start()] if match.start() else ''
                after = text[match.end():match.end()+1]
                if (before and (before.isalnum() or before == '_')) or (after and (after.isalnum() or after == '_')):
                    return value
            return self._labels[value]
        return re.sub(pattern, replacement, text)

    def observation(self, observation):
        self.learn(observation)
        clean = copy.deepcopy(observation)
        changed = []
        for row in clean.get('lines', []):
            original = row['text']
            row['text'] = self.text(original)
            if row['text'] != original:
                changed.append(row['line'])
        # A recognized value crossing fragments cannot be safely replaced in
        # either isolated row. Withhold those rows rather than expose its parts.
        groups = []
        for row in observation.get('lines', []):
            if groups and row.get('source_line') is not None and row.get('source_line') == groups[-1][-1].get('source_line') and row['line'] == groups[-1][-1]['line']+1:
                groups[-1].append(row)
            else:
                groups.append([row])
        withheld = set()
        for group in groups:
            if len(group) > 1:
                combined = ''.join(r['text'] for r in group)
                if self.text(combined) != combined:
                    withheld.update(r['line'] for r in group)
        for row in clean.get('lines', []):
            if row['line'] in withheld:
                row['text'] = '[REDACTED-PRIVATE-FRAGMENT]'
                if row['line'] not in changed:
                    changed.append(row['line'])
        # Facts containing a hidden argument must not bypass the source view.
        # Drop them instead of silently breaking their source fact hash.
        facts = clean.get('operation_facts', [])
        clean['operation_facts'] = [f for f in facts if all(self.text(s) == s for s in string_values(f))]
        clean['model_projection'] = {
            'method': VERSION, 'changed_lines': changed,
            'view_lines_sha256': hashlib.sha256(canonical(clean.get('lines', []))).hexdigest(),
            'original_output_sha256': observation.get('output_sha256'),
            'suppressed_operation_facts': len(facts)-len(clean['operation_facts']),
            'scan_truncated': self.scan_truncated,
            'scope': 'Projected quotes at original coordinates; output_sha256 identifies private VM output, not projected bytes. '
                     'Known literal/email/token patterns only; unknown/encoded secrets and fragmented values may remain.',
        }
        return clean

    def refresh(self, evidence):
        """Newly recognized values also disappear from previously held contexts."""
        for record in evidence.values():
            record['line_map'] = {n: self.text(s) for n, s in record.get('line_map', {}).items()}
            record['operation_facts'] = [f for f in record.get('operation_facts', [])
                                       if all(self.text(s) == s for s in string_values(f))]
