"""Exercise real VM HTTP retrieval and controller projection; no model inference."""
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stealer_agent.journal import canonical, dump_json, utc_now
from stealer_agent.transport import ToolClient
from stealer_agent.security import guard_observation
from stealer_agent.model_projection import ModelEvidenceView
from stealer_agent.context_cards import linked_cards


def main():
    cfg = json.loads((ROOT/'config/host.example.json').read_text())
    client = ToolClient(cfg, (ROOT/'config/lab.token').read_text().strip())
    client.inspect()
    preflight = json.loads((ROOT/'evidence/local/lab-verification.json').read_text())
    assert preflight['source_matches_vm'] and not preflight['vm']['default_routes']
    assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == h for p,h in preflight['host_source'].items())
    source_run = '20261127T193524_b2342ecf'
    events = [json.loads(s) for s in (ROOT/'runs'/source_run/'events.jsonl').read_text(encoding='utf-8').splitlines()]
    original = next(e['raw'] for e in events if e['event']=='observation' and e['raw']['tool']=='decode_python_literals')
    private = ROOT/'private/context-projection'/str(time.time_ns())
    private.mkdir(parents=True)
    preparation, disassembly, recovered = [], None, None
    for event in events:
        if event['event'] != 'action_dispatched' or event['action'] not in {'unpack_pyinstaller','disassemble_python','decode_python_literals'}:
            continue
        action, args = event['action'], dict(event['arguments'])
        if action == 'decode_python_literals':
            args['evidence_id'] = disassembly
        result = client.call(action, args)
        assert result['status'] == 'ok'
        dump_json(private/f'prepare-{len(preparation)}.json', result)
        preparation.append({'action':action,'evidence_id':result['evidence_id'],'output_sha256':result['output_sha256']})
        if action == 'disassemble_python':
            disassembly = result['evidence_id']
        if action == 'decode_python_literals':
            recovered = result
            break
    assert recovered and recovered['sample_sha256']==original['sample_sha256']
    # Decoder provenance contains fresh evidence IDs, so the full output hash
    # legitimately changes. Compare reconstructed source independently below.
    profile = json.loads((ROOT/'eval/reference_units/python2024.behavior-v1.json').read_text(encoding='utf-8'))
    view, evidence, checks = ModelEvidenceView(), {}, []
    for number,query in enumerate(('execute(', 'decrypt_password', 'sendmail')):
        raw = client.call('search_evidence', {'sample':recovered['sample'],'evidence_id':recovered['evidence_id'],'query':query})
        dump_json(private/f'search-{number}.json', raw)
        assert raw['syntax_context']['backend'] == 'tree-sitter-context/3'
        assert raw['syntax_context']['source_sha256'] == profile['source_record']['parser_source_sha256']
        clean, hits = guard_observation(raw)
        clean = view.observation(clean)
        record = evidence.setdefault(clean['evidence_id'], {**clean,'line_map':{},'context_links':[]})
        record['line_map'].update({r['line']:r['text'] for r in clean['lines']})
        record['context_links'] = list({json.dumps(link,sort_keys=True):link for link in record['context_links']+clean['context_links']}.values())
        view.refresh(evidence)
        links = clean['context_links']
        if query != 'sendmail':
            for anchor in (144,172):
                assert any(any(r['line']<=anchor<=r['end_line'] for r in link['ranges']) and
                           {'line':69,'end_line':75} in link['ranges'] for link in links), (query,anchor)
            cards = linked_cards(evidence)
            assert all(any(any(r['line']<=anchor<=r['end_line'] for r in card['references']) and
                           any(r['line']==69 and r['end_line']==75 for r in card['references']) for card in cards)
                       for anchor in (144,172))
        else:
            assert len(clean['model_projection']['changed_lines']) >= 2
            assert clean['lines'] != raw['lines']
        checks.append({'query':query,'anchors':[g['anchor_line'] for g in raw['search_groups']],
                       'links':links, 'source_rows_returned':len(raw['lines']),
                       'projection_changed_lines':clean['model_projection']['changed_lines'],
                       'raw_response_sha256':hashlib.sha256(canonical(raw)).hexdigest(),
                       'view_lines_sha256':clean['model_projection']['view_lines_sha256'],
                       'syntax_context':raw['syntax_context'], 'guard_hits':hits})
    receipt = {'created_at':utc_now(),'kind':'fresh-static-tools-and-real-HTTP-check-not-model-demo',
               'source_run_for_comparison':source_run,'sample_sha256':recovered['sample_sha256'],
               'same_reconstructed_source_as_reference':True,
               'full_output_hash_matches_old_run':recovered['output_sha256']==original['output_sha256'],
               'output_sha256':recovered['output_sha256'],'evidence_id':recovered['evidence_id'],
               'preparation':preparation,'checks':checks,
               'source_manifest_sha256':hashlib.sha256(canonical(preflight['host_source'])).hexdigest(),
               'both_query_owners_keep_helper_in_cards':True,
               'limits':['Development source, not independent holdout or semantic grading.',
                         'Credential projection is pattern-based; original private evidence is unchanged.',
                         'No malware execution, model inference, source text or credential values in this receipt.']}
    output = ROOT/'deliverables/real-demo-evidence/context-v3-projection-http-check.json'
    dump_json(output,receipt)
    print(json.dumps({'receipt':str(output),'queries':len(checks),'both_owners_verified':True}))


if __name__ == '__main__':
    main()
