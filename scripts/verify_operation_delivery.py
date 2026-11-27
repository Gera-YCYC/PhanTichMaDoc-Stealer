"""Check real VM search -> bounded parser -> host guard, without model inference."""
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import canonical, dump_json, utc_now, verify_journal
from stealer_agent.security import guard_observation
from stealer_agent.transport import ToolClient


def main():
    config = json.loads((ROOT/'config/host.example.json').read_text())
    client = ToolClient(config, (ROOT/'config/lab.token').read_text().strip())
    client.inspect()
    source = json.loads((ROOT/'evidence/local/lab-verification.json').read_text())
    assert source['source_matches_vm'] and not source['vm']['default_routes']
    # Refuse a stale preflight after any parser/controller edit.
    for name,digest in source['host_source'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest
    cases = [
        ('20261127T180215_b3a8ccf4','decompile_dotnet',['UploadFile','.UploadFile(','Encoding.ASCII.GetString'],
         {'file_upload','response_text_decode'}),
        ('20261127T175019_6cbdf3e9','decode_python_literals',['cursor.execute','decrypt_password','sendmail','make_archive'],
         {'sql_select','database_open','smtp_send','archive_create','aes_gcm_decrypt'}),
    ]
    receipts = []
    private = ROOT/'private/operation-delivery'/str(time.time_ns())
    private.mkdir(parents=True)
    for run,tool,queries,expected in cases:
        path = ROOT/'runs'/run
        verify_journal(path/'events.jsonl')
        report = json.loads((path/'report.private.json').read_text(encoding='utf-8'))
        events = [json.loads(s) for s in (path/'events.jsonl').read_text(encoding='utf-8').splitlines()]
        captured = next(e['raw'] for e in events if e['event']=='observation' and
                        e['raw']['tool']==tool and e['raw']['status']=='ok')
        # Evidence IDs are intentionally scoped to one service session. Re-run
        # the trusted static tools after sync/restart, never inject old records.
        preparation = []
        last_disassembly = None
        pipeline = {'decompile_dotnet'} if tool=='decompile_dotnet' else {
            'unpack_pyinstaller','disassemble_python','decode_python_literals'}
        original = None
        for event in events:
            if event['event']!='action_dispatched' or event['action'] not in pipeline:
                continue
            action=event['action']
            arguments=dict(event['arguments'])
            if action=='decode_python_literals':
                assert last_disassembly is not None
                arguments['evidence_id']=last_disassembly
            response=client.call(action,arguments)
            dump_json(private/f'{run}-prepare-{len(preparation)}.json',response)
            assert response['status']=='ok', (action,response['status'])
            preparation.append({'action':action,'backend':response['backend'],
                                'evidence_id':response['evidence_id'],'output_sha256':response['output_sha256']})
            if action=='disassemble_python':
                last_disassembly=response['evidence_id']
            if action==tool:
                original=response
                break
        assert original is not None
        assert original['sample_sha256']==captured['sample_sha256']
        seen = set()
        calls = []
        for index,query in enumerate(queries):
            started = time.perf_counter()
            response = client.call('search_evidence', {'sample':report['sample'],
                                   'evidence_id':original['evidence_id'],'query':query})
            elapsed = time.perf_counter()-started
            dump_json(private/f'{run}-{index}.json',response)
            assert response['status']=='ok'
            assert response['sample_sha256']==original['sample_sha256']
            assert response['output_sha256']==original['output_sha256']
            assert response.get('operation_backend')=='static-operation-facts/4'
            assert 'operation_status' not in response
            clean,hits = guard_observation(response)
            assert hits==0
            facts = clean['operation_facts']
            # Generic search may land on LateGet, deliberately unsupported by
            # this direct-binding parser. Empty facts do not imply a clean file.
            line_map = {r['line']:r['text'] for r in clean['lines']}
            for fact in facts:
                body={k:v for k,v in fact.items() if k!='fact_id'}
                assert fact['fact_id']=='op_'+hashlib.sha256(canonical(body)).hexdigest()[:16]
                assert fact['sample_sha256']==original['sample_sha256']
                assert fact['output_sha256']==original['output_sha256']
                assert all(n in line_map for r in fact['ranges'] for n in range(r['line'],r['end_line']+1))
                seen.add(fact['operation'])
            calls.append({'query':query,'elapsed_s':round(elapsed,4),'fact_count':len(facts),
                          'operations':sorted({f['operation'] for f in facts}),
                          'response_sha256':hashlib.sha256(canonical(response)).hexdigest(),
                          'all_fact_hashes_and_ranges_verified':True,'guard_hits':hits,
                          'empty_fact_set':not facts})
        assert expected <= seen, (run, expected-seen)
        receipts.append({'source_run':run,'sample_sha256':original['sample_sha256'],
                         'evidence_id':original['evidence_id'],'output_sha256':original['output_sha256'],
                         'fresh_static_tools':preparation,
                         'same_source_output_as_captured':original['output_sha256']==captured['output_sha256'],
                         'calls':calls,'expected_operations_observed':True})
    receipt={'created_at':utc_now(),'kind':'live-VM-HTTP-parser-guard-check-not-SLM-demo',
             'backend':'static-operation-facts/4','source_matches_vm':True,
             'source_manifest_sha256':hashlib.sha256(canonical(source['host_source'])).hexdigest(),
             'cases':receipts,'limits':['Re-runs static tools on development samples with actions captured from earlier runs; not a new holdout.',
             'No model inference or malware execution; no precision, recall or verdict score.',
             'Argument values, source, credentials and endpoint text are excluded from the public receipt.']}
    output=ROOT/'deliverables/real-demo-evidence/typed-operations-v4-delivery-check.json'
    dump_json(output,receipt)
    print(json.dumps({'receipt':str(output),'cases':len(receipts),
                      'calls':sum(len(r['calls']) for r in receipts),'all_checks_passed':True}))


if __name__=='__main__':
    main()
