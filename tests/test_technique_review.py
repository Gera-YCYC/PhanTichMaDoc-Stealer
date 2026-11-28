from stealer_agent.technique_review import POLICIES, candidate_ranges, review_techniques


def test_ranges_preserve_gaps_and_require_nearby_evidence():
    record = {'evidence_id': 'e1', 'line_map': {
        10: 'path = "Login Data"', 15: '# SELECT password_value', 70: 'SELECT password_value'}}
    patterns, _ = POLICIES['T1555.003']
    assert candidate_ranges(record, patterns) == []
    record['line_map'][18] = 'query = "SELECT password_value FROM logins"'
    assert not candidate_ranges(record, patterns)
    record['line_map'][19] = 'rows = cursor.fetchall()'
    refs = candidate_ranges(record, patterns)
    assert [r['line'] for r in refs] == [10, 15, 18]
    assert refs[-1]['end_line'] == 19


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
