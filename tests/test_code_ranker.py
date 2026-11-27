import hashlib
import json
from pathlib import Path
import pytest

from training.train_ranker import train
from vm_tools.code_search import FEATURES, MODEL_PATH, load_model, select_contexts


def test_frozen_training_reproduces_checkpoint_without_test_updates():
    root=Path(__file__).resolve().parents[1]
    raw=(root/'training/corpus/code-reference-v1.json').read_bytes()
    data=json.loads(raw); model=load_model()
    w,b,history=train(data)
    assert model['dataset_sha256']==hashlib.sha256(raw).hexdigest()
    # Windows CRT and Linux libm may differ at the last floating-point bit.
    assert w==pytest.approx(model['weights'],rel=0,abs=1e-12)
    assert b==pytest.approx(model['bias'],rel=0,abs=1e-12)
    assert history[-1]['train_binary_cross_entropy_plus_l2']<history[0]['train_binary_cross_entropy_plus_l2']
    for row in data['rows']:
        if row['split']!='train': row['label']=1-row['label']
    w2,b2,_=train(data)
    assert (w,b)==(w2,b2)


def test_search_keeps_actual_hit_and_immutable_line_offsets():
    lines=[{'line':i+1,'text':'// filler '+str(i)} for i in range(120)]
    lines[2]['text']='public static void SendData(string value)'
    lines[70]['text']='client.SendData(value);'
    record={'lines':lines}
    selected,groups,count=select_contexts(record,'SendData',load_model(),max_contexts=1,max_chars=500)
    assert count==2 and groups[0]['anchor_line']==71
    assert any(r==lines[70] for r in selected)
    assert all(r==lines[r['line']-1] for r in selected)
    assert sum(len(r['text'])+50 for r in selected)<=500
