from stealer_agent.technique_review import POLICIES, candidate_ranges, review_techniques


def test_candidate_needs_the_intervening_source_and_rejects_redacted_gaps():
    record = {'evidence_id': 'e1', 'line_map': {
        10: 'path = "Login Data"', 15: '# SELECT password_value', 70: 'SELECT password_value'}}
    patterns, _ = POLICIES['T1555.003']
    assert candidate_ranges(record, patterns) == []
    record['line_map'][18] = 'query = "SELECT password_value FROM logins"'
    assert not candidate_ranges(record, patterns)
    record['line_map'][19] = 'rows = cursor.fetchall()'
    assert not candidate_ranges(record, patterns)
    for n in range(11, 18):
        record['line_map'].setdefault(n, 'pass')
    record['line_map'][13] = '[REDACTED-INJECTION]'
    assert not candidate_ranges(record, patterns)
    record['line_map'][13] = 'bound = original'
    refs = candidate_ranges(record, patterns)
    assert [(r['line'], r['end_line']) for r in refs] == [(10, 19)]
    assert 'bound = original' in refs[0]['quote']


def test_long_contiguous_source_fits_report_citation_contract():
    record = {'evidence_id': 'e1', 'line_map': {n: 'pass' for n in range(1, 50)}}
    record['line_map'].update({1: 'start anchor', 49: 'end anchor'})
    refs = candidate_ranges(record, ('start anchor', 'end anchor'))
    assert len(refs) == 2 and refs[0]['end_line'] + 1 == refs[1]['line']
    assert refs[0]['line'] == 1 and refs[-1]['end_line'] == 49
    assert all(0 <= ref['end_line'] - ref['line'] < 40 for ref in refs)


def test_candidate_cannot_self_assign_technique():
    record = {'evidence_id': 'e1', 'sample_sha256': 'a' * 64, 'status': 'ok', 'tool': 'decompile_python',
              'line_map': {5: 'image = ImageGrab.grab()'}}
    class Log:
        def append(self, event, **fields):
            assert event == 'technique_review_decision' and fields['technique_id'] == 'T1113'
    def decline(messages, schema, phase, delivered):
        assert phase == 'technique_review' and delivered[0]['lines'][0]['line'] == 5
        return {'assessment': 'Receiver unresolved', 'supported': False}
    claims, accepted = [], []
    review_techniques({'e1': record}, record['sample_sha256'], decline, Log(), claims, accepted)
    assert not claims and not accepted
