"""Export a pinned development run and explicit source-audit judgments.

Not an automatic semantic grader. New reports require their own source review.
Public artifacts contain only allowlisted metadata, coordinates and audit notes.
"""
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import dump_json, verify_journal
from scripts.replay_card_report import reconstruct
from eval.claim_audit import calculate
from eval.projection_audit import calculate as projection_score

RUN = '20261127T230331_8bd30a1f'
RAW_SHA = '79335444bbf2cbf2912658accf389db4c782723f1e733610b8789f0e7a912390'
NOTES = {
    'C1': ('correct', 'make_archive uses zip format and the temporary Browser directory; its returned archive path is Browser.zip. No contents or runtime success asserted.'),
    'C2': ('correct', 'Archive body, return value, caller and complete send_email body are supplied. The archive path is read, attached, serialized and passed to sendmail after login. Static capability, not successful delivery.'),
    'C3': ('correct', 'The exact SMTP hostname literal is assigned and used by the SMTP constructor. This is a configured destination candidate, not confirmed malicious infrastructure or observed traffic.'),
    'C4': ('correct', 'The helper builds the Login Data path, copies it into the temporary login_db path and opens that copy with sqlite3.connect.'),
    'C5': ('correct', 'Connection and SELECT are both visible; selected password_value is subsequently passed into the supplied decrypt helper. The query itself is not claimed to perform decryption.'),
    'C6': ('unsupported', 'IOC value is a source expression containing a variable and concatenation, not an extracted concrete path literal. Quote overlap cannot establish that value as an indicator.'),
    'C7': ('correct', 'The supplied from-import binds CryptUnprotectData to win32crypt; the call takes the processed master_key and selects tuple element 1. Qualified API naming here is supported by the import.'),
    'C8': ('unsupported', 'Reading into c is present, but the claim promotes the parser API-family label io.TextIOBase.read into the actual called implementation. The source only shows read on the file object returned by open; it does not establish invocation of that abstract base-class method.'),
    'C9': ('unsupported', 'IOC value is the expression path plus a suffix rather than a resolved literal indicator. The path variable is not a literal value.'),
    'C10': ('correct', 'The complete save_results helper opens the interpolated browser/data_type path in write mode and writes content. Braces in this behavior description identify the template, not a literal IOC.'),
    'C11': ('correct', 'The helper conditionally opens Combined_Autofill.txt in append mode and writes content. The claim describes implemented capability, not unconditional execution.'),
    'C12': ('unsupported', 'The submitted IOC combines a variable with interpolation placeholders and does not establish a concrete path value.'),
    'C13': ('correct', 'Visible shutil.copy takes cards_db and the temporary destination; adjacent sqlite3.connect establishes the copied database use. No plaintext card contents are asserted.'),
    'C14': ('correct', 'Visible sqlite3.connect opens the temporary cards_db path. It does not prove query results, decryption or successful runtime access.'),
    'C15': ('unsupported', 'The IOC value is an incomplete variable-containing expression; the text is only a variable name. Neither establishes a concrete indicator.'),
    'C16': ('correct', 'The visible cursor.execute call receives the literal SELECT of tab_url and target_path from downloads, followed by fetchall. This is a narrow static query description, not a claim about actual rows or exfiltration.'),
    'C17': ('correct', 'The supplied getAutofill excerpt builds a Web Data path, copy2 copies it into tempfold, sqlite3 connects and execute selects non-null autofill values. No theft verdict or successful execution asserted.'),
    'C18': ('correct', 'Web Data is a visible filename suffix used by the helper. It is only a generic artifact-name candidate shared with legitimate browsers, not a specific malicious network indicator.'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    path = ROOT / 'runs' / RUN
    verify_journal(path / 'events.jsonl')
    events_bytes = (path / 'events.jsonl').read_bytes()
    events = [json.loads(s) for s in events_bytes.splitlines()]
    assert events[-1]['event'] == 'run_finished'
    raw_bytes = (path / 'report.model-raw.json').read_bytes()
    assert sha(raw_bytes) == RAW_SHA, 'Changed report requires a new audit'
    raw = json.loads(raw_bytes)
    final = json.loads((path / 'report.private.json').read_bytes())
    evidence = reconstruct(events)
    assert set(NOTES) == {c['id'] for c in raw['claims']}
    rows = []
    for claim in raw['claims']:
        refs = []
        for ref in claim['evidence']:
            record = evidence[ref['evidence_id']]
            assert record['sample_sha256'] == final['sample_sha256']
            quote = '\n'.join(record['line_map'][n] for n in range(ref['line'], ref['end_line'] + 1))
            assert quote == ref['quote']
            refs.append({k: ref[k] for k in ('evidence_id', 'line', 'end_line')} |
                        {'projected_quote_sha256': sha(quote.encode())})
        label, reason = NOTES[claim['id']]
        rows.append({'claim_id': claim['id'], 'label': label, 'grounded': label == 'correct',
                     'reviewer': 'automated source audit, not Qwen self-review or human approval',
                     'truth_reference': refs, 'reason': reason})
    audit = {'run_id': RUN, 'sample_sha256': final['sample_sha256'], 'raw_report_sha256': RAW_SHA,
             'journal_sha256': sha(events_bytes), 'dataset_origin': 'public-development-sample-source-audit',
             'human_reviewers': [], 'all_submitted_quotes_verified_against_projected_observations': True,
             'scope': 'All raw claims including rejected candidates; labels remain open to independent correction.',
             'claims': rows}
    out = ROOT / 'deliverables/real-demo-evidence'
    dump_json(ROOT / 'eval/adjudications/python2024-cards-v9-full-audit.json', audit)
    score = calculate(raw_bytes, final['analysis'], audit)
    dump_json(out / 'python2024-cards-v9-claim-score.json', score)
    projection = projection_score(events, raw)
    dump_json(out / 'python2024-cards-v9-projection-audit.json', projection)
    receipt = {k: final[k] for k in ('run_id', 'sample', 'sample_sha256', 'status', 'successful_tools', 'metrics', 'acceptance')}
    receipt.update(kind='real-local-model-vm-experiment-metadata', report_method='evidence-cards/9',
        model={k: final['model'][k] for k in ('tag', 'digest', 'size_bytes', 'details')},
        source_manifest_sha256=next(e['manifest_sha256'] for e in events if e['event'] == 'source_version'),
        journal_sha256=sha(events_bytes), journal_chain_verified=True, raw_report_sha256=RAW_SHA,
        raw_claims_by_kind=dict(Counter(c['kind'] for c in raw['claims'])),
        raw_claims=len(raw['claims']), accepted_claims=len(final['analysis']['claims']),
        rejected_claims=len(final['analysis']['rejected_claims']), verdict=final['analysis']['verdict'],
        course_quality_gate_passed=False, no_sample_execution=True,
        limits=['One development sample; not a full-corpus acceptance test.',
                'API-label and expression-as-IOC errors retained, including those accepted by same-model review.',
                'No ATT&CK assertion was returned; recall/F1 not inferred from claim precision.',
                'Raw journals and excerpts remain local; this metadata does not approve them for publication.'])
    dump_json(out / 'python2024-cards-v9-run.json', receipt)
    print(json.dumps({'run_id': RUN, 'raw': score['raw'], 'after_filter': score['after_filter']}))


if __name__ == '__main__':
    main()
