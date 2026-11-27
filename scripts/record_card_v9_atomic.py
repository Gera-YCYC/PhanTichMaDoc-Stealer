"""Reproduce explicit atomic scoring for the pinned v9 development report.

The reference is expanded after source inspection to cover correct out-of-scope
claims, not by silently dropping them. It is not a blind or human-approved test.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.record_card_v9_results import RUN, RAW_SHA, NOTES
from stealer_agent.journal import canonical, dump_json
from eval.atomic_units import calculate


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    original = (ROOT / 'eval/reference_units/python2024.atomic-v1.json').read_bytes()
    assert sha(original) == '4c2bcd775e6b282c53e86aef59409200d8863be06963e3c8a1aeea2c9f1f2bf6'
    profile = copy.deepcopy(json.loads(original))
    profile['profile_id'] = 'python2024.atomic-development/2'
    profile['scope'] = 'Browser-password/card, archive/SMTP chain plus explicitly enumerated download/autofill operations; not whole-binary recall.'
    profile['extension_reason'] = 'Five independently source-inspected units added after the v9 run to retain its correct out-of-scope assertions. Original 29 units unchanged.'
    profile['source_references'].append({'path': 'eval/reference_units/python2024.atomic-v1.json', 'sha256': sha(original)})
    profile['not_covered'] = ['Other browser-history behavior and unenumerated download/autofill operations',
                              'Whole-module reachability', 'Runtime execution', 'Credential literal publication',
                              'Whole-corpus/whole-course acceptance']
    eid = 'ev_a789dcd941044224'
    additions = [
        ('A30', 'behavior', 'Appends non-null Autofill content to Combined_Autofill.txt.', 116, 131),
        ('A31', 'behavior', 'Executes SELECT tab_url, target_path FROM downloads.', 218, 219),
        ('A32', 'behavior', 'Copies Web Data into the generated tempfold path in getAutofill.', 233, 246),
        ('A33', 'behavior', 'Executes SELECT * FROM autofill WHERE value IS NOT NULL.', 244, 249),
        ('A34', 'ioc', 'Web Data is a static filename-suffix candidate, common to legitimate browser files; not a unique malicious IOC.', 238, 244),
    ]
    profile['units'].extend({'id': 'PY24-' + key, 'kind': kind, 'proposition': text,
                             'source_references': [{'evidence_id': eid, 'line': start, 'end_line': end}]}
                            for key, kind, text, start, end in additions)
    target = ROOT / 'eval/reference_units/python2024.atomic-v2.json'
    dump_json(target, profile)
    profile_bytes = target.read_bytes()
    run = ROOT / 'runs' / RUN
    raw_bytes = (run / 'report.model-raw.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA
    raw = json.loads(raw_bytes)
    checked = json.loads((run / 'report.private.json').read_bytes())['analysis']
    checked_bytes = canonical(checked)
    # Boundaries are exact substrings in this pinned report, not a generic NLP rule.
    units = {'C1': [('A18', None)], 'C2': [('A25', ' with the zipped'), ('A26', ' after authenticating'), ('A24', None)],
             'C3': [('A27', None)], 'C4': [('A05', None)],
             'C5': [('A06', ' and executes'), ('A07', None)], 'C6': [(None, None)],
             'C7': [('A03', None)], 'C8': [(None, None)], 'C9': [(None, None)],
             'C10': [('A15', None)], 'C11': [('A30', None)], 'C12': [(None, None)],
             'C13': [('A10', None)], 'C14': [('A11', None)], 'C15': [(None, None)],
             'C16': [('A31', None)], 'C17': [('A32', ' and then queries'), ('A33', None)],
             'C18': [('A34', None)]}
    mapping = {'schema_version': 1, 'sample_sha256': profile['sample_sha256'],
               'profile_sha256': sha(profile_bytes), 'raw_report_sha256': RAW_SHA,
               'checked_report_sha256': sha(checked_bytes),
               'reviewer': 'automated source audit; no human or lecturer approval',
               'method': 'Explicit exhaustive spans; one assertion per source operation/indicator, including all rejected candidates. Correct API role plus a false implementation qualifier remains one unsupported operation.',
               'claims': []}
    audit = json.loads((ROOT / 'eval/adjudications/python2024-cards-v9-full-audit.json').read_bytes())
    refs = {r['claim_id']: r['truth_reference'] for r in audit['claims']}
    for claim in raw['claims']:
        cid, text, cursor, atoms = claim['id'], claim['text'], 0, []
        for key, next_start in units[cid]:
            end = text.index(next_start, cursor) if next_start else len(text)
            unit_id = 'PY24-' + key if key else None
            label, reason = NOTES[cid]
            assert (label == 'correct') == bool(unit_id)
            atoms.append({'start': cursor, 'end': end, 'label': label,
                          'unit_key': unit_id or ('v9-unsupported-' + cid), 'reference_id': unit_id,
                          'reason': reason, 'source_references': refs[cid]})
            cursor = end
        mapping['claims'].append({'claim_id': cid, 'atoms': atoms})
    dump_json(ROOT / 'eval/adjudications/python2024-cards-v9-atomic-mapping.json', mapping)
    score = calculate(profile_bytes, raw_bytes, checked_bytes, mapping)
    dump_json(ROOT / 'deliverables/real-demo-evidence/python2024-cards-v9-atomic-score.json', score)
    print(json.dumps({'profile_id': profile['profile_id'], 'raw': score['raw'], 'after_filter': score['after_filter']}))


if __name__ == '__main__':
    main()
