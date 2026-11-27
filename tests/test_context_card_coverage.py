from stealer_agent.context_cards import linked_cards
from stealer_agent.evidence_cards import select_cards


def evidence():
    eid='ev_'+'a'*16
    rows={n:'value_'+str(n)+' = handle(value)' for n in range(1,40)}
    links=[
        {'call_line':2,'ranges':[{'line':1,'end_line':4},{'line':10,'end_line':18},{'line':25,'end_line':29}]},
        {'call_line':12,'ranges':[{'line':10,'end_line':14},{'line':25,'end_line':29}]},
        {'call_line':34,'ranges':[{'line':32,'end_line':37},{'line':10,'end_line':16}]},
    ]
    return {eid:{'tool':'decompile_python','status':'ok','sample_sha256':'b'*64,
                 'line_map':rows,'context_links':links,'focus_groups':[[12],[26],[34]]}}


def test_subsumed_link_preserves_focus_and_leaves_room_for_different_caller():
    cards=linked_cards(evidence(),max_cards=2)
    assert len(cards)==2
    assert cards[0]['focus_lines']==[2,12]
    assert cards[0]['subsumed_context_count']==1
    assert cards[1]['reference']['line']==32


def test_search_hit_in_secondary_reference_does_not_create_partial_duplicate():
    data=evidence()
    record=next(iter(data.values()))
    record['context_links']=record['context_links'][:1]
    record['line_map']={n:v for n,v in record['line_map'].items() if 1<=n<=4 or 10<=n<=18 or 25<=n<=29}
    record['focus_groups']=[[12],[26]]
    cards=select_cards(data,max_cards=4)
    assert len(cards)==1
    assert {2,12,26}<=set(cards[0]['focus_lines'])
    assert len(cards[0]['references'])==3


def test_missing_dependency_line_cannot_be_restored_by_deduplication():
    data=evidence()
    next(iter(data.values()))['line_map'].pop(27)
    cards=linked_cards(data,max_cards=4)
    assert all(not any(r['line']<=27<=r['end_line'] for r in c['references']) for c in cards)
    assert len(cards)==1 and cards[0]['reference']['line']==32
