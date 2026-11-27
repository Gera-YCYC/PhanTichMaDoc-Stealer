"""Bounded raw-file literal candidates with byte coordinates; never executes code."""
import re
from .carchive_index import application_names
from stealer_agent.security import INJECTION, SECRET
from stealer_agent.redaction import EMAIL, collect_literals

INTEREST = re.compile(r'password|passwd|login|cookie|credential|webhook|telegram|discord|'
                      r'encrypted_key|local state|credit|wallet|upload|smtp|screenshot|'
                      r'cryptunprotect|sqlite|keylog|steal|exfil|grabber', re.I)
PATH = re.compile(r'[A-Za-z_][A-Za-z0-9_.\\/-]{4,}\.(?:pyc?|pyd|dll|exe|db|txt)\b', re.I)


def extract(data):
    if not 1 <= len(data) <= 32_000_000:
        raise ValueError('Candidate input outside size bound')
    selected, seen_count, truncated = {}, 0, False
    for encoding, pattern in (('ascii', rb'[\x20-\x7e]{6,}'),
                              ('utf-16le', rb'(?:[\x20-\x7e]\x00){6,}')):
        for match in re.finditer(pattern, data):
            seen_count += 1
            if seen_count > 500_000:
                truncated = True
                break
            # Whole printable runs only: do not invent fragments from long blobs.
            if len(match[0]) > (150 if encoding == 'ascii' else 300):
                continue
            value = match[0].decode(encoding)
            interest = len(INTEREST.findall(value))
            path = bool(PATH.search(value))
            if not (interest or path) or INJECTION.search(value) or SECRET.search(value) or EMAIL.search(value):
                continue
            secrets, _ = collect_literals([value])
            if secrets:
                continue
            score = 10 * interest + int(path)
            row = {'value': value, 'encoding': encoding, 'offset': match.start(),
                   'selection_score': score}
            if value not in selected:
                selected[value] = row
            if len(selected) > 120:
                ranked = sorted(selected.values(), key=lambda r: (-r['selection_score'], r['offset'], r['value']))[:60]
                selected = {r['value']: r for r in ranked}
        if truncated:
            break
    try:
        archive = application_names(data)
    except ValueError as exc:
        archive = {'status': 'invalid_toc', 'error': str(exc), 'application_entries': []}
    for row in archive['application_entries']:
        if not INJECTION.search(row['value']) and not SECRET.search(row['value']) and not EMAIL.search(row['value']):
            selected[row['value']] = row
    rows = sorted(selected.values(), key=lambda r: (-r['selection_score'], r['offset'], r['value']))[:60]
    for index, row in enumerate(rows, 1):
        row['id'] = 'S' + str(index)
    return {'representation': 'original_file_bytes', 'candidates': rows, 'runs_examined': seen_count,
            'scan_truncated': truncated, 'archive_status': archive['status'],
            'selection': 'application_entry_identity_then_lexical_interest_then_file_path; not a malware verdict'}
