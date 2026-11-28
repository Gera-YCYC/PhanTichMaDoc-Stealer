from vm_tools.evidence import EvidenceStore
from stealer_agent.contracts import validate_action


def test_miss_points_to_existing_readable_pages_without_exporting_names(tmp_path):
    store = EvidenceStore(tmp_path,page_chars=125)
    source = ['// fake.DoNotRead()', 'var x = "hidden.InLiteral()";', 'using System;',
              'cache.Store(value);', '}', ' ', 'result = stream.Read(buffer);']
    record = store.add(sample='fixture',sample_sha256='a'*64,tool='decompile_dotnet',backend='test',text='\n'.join(source))
    eid = record['evidence_id']
    miss = store.search(eid,'a'*64,'absent-query')
    assert miss['hit_count']==0 and miss['lines']==[]
    hints = miss['navigation_pages']
    assert hints
    for hint in hints:
        assert set(hint) == {'page','anchor'} and hint['anchor'] in (4,7)
        page = store.page(eid,hint['page'])
        assert hint['anchor'] == page['navigation_anchor']
        assert hint['anchor'] in {r['line'] for r in page['lines']}


def test_occurrence_order_ablation_never_loads_checkpoint(tmp_path,monkeypatch):
    store = EvidenceStore(tmp_path)
    record = store.add(sample='fixture',sample_sha256='a'*64,tool='decompile_dotnet',backend='test',
                       text='// item\n' + '\n'.join(['x=1;']*24) + '\nservice.item();')
    def unexpected():
        raise AssertionError('Baseline must use source order')
    monkeypatch.setattr('vm_tools.evidence.load_model',unexpected)
    args={'sample':'fixture','query':'item','evidence_id':record['evidence_id'],'occurrence_order':True}
    validate_action({'action':'search_evidence','arguments':args,'report':None,'reason':'Check retrieval order'})
    out=store.search(record['evidence_id'],'a'*64,'item',occurrence_order=True)
    assert out['retrieval_model_sha256'] is None and out['search_groups'][0]['anchor_line']==1
