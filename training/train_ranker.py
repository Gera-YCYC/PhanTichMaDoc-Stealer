"""Deterministic full-batch logistic regression, standard library CPU only.

No sample execution, neural-library pickle files, cloud calls or SLM updates.
Run logs and JSON weights are retained even if held-out scores are poor.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import time

ROOT=Path(__file__).resolve().parents[1]


def sigmoid(x):
    return 1/(1+math.exp(-max(-40,min(40,x))))


def probability(row,weights,bias):
    return sigmoid(bias+sum(w*x for w,x in zip(weights,row['features'])))


def metrics(rows,weights,bias):
    tp=fp=tn=fn=0
    for r in rows:
        predicted=probability(r,weights,bias)>=0.5
        if predicted and r['label']: tp+=1
        elif predicted: fp+=1
        elif r['label']: fn+=1
        else: tn+=1
    p=tp/(tp+fp) if tp+fp else None
    rec=tp/(tp+fn) if tp+fn else None
    groups={}
    for r in rows: groups.setdefault((r['sample'],r['query']),[]).append(r)
    first=sum(min(g,key=lambda r:r['line'])['label'] for g in groups.values())
    learned=sum(max(g,key=lambda r:(probability(r,weights,bias),-r['line']))['label'] for g in groups.values())
    return {'n':len(rows),'tp':tp,'fp':fp,'tn':tn,'fn':fn,'precision':p,'recall':rec,
            'accuracy':(tp+tn)/len(rows) if rows else None,
            'query_groups':len(groups), 'first_occurrence_hit_at_1':first/len(groups) if groups else None,
            'learned_hit_at_1':learned/len(groups) if groups else None,
            'scope':'structural relevance in frozen candidate subset; not behavior F1 or full-document retrieval'}


def train(data,epochs=300,lr=0.3,l2=0.01):
    train_rows=[r for r in data['rows'] if r['split']=='train']
    n=len(train_rows)
    w=[0.0]*len(data['features']); bias=0.0; history=[]
    if not n or {r['label'] for r in train_rows}!={0,1}: raise ValueError('Both training classes required')
    for epoch in range(epochs+1):
        probs=[probability(r,w,bias) for r in train_rows]
        loss=-sum(r['label']*math.log(max(p,1e-15))+(1-r['label'])*math.log(max(1-p,1e-15))
                  for r,p in zip(train_rows,probs))/n+l2*sum(v*v for v in w)/2
        history.append({'epoch':epoch,'train_binary_cross_entropy_plus_l2':loss})
        if epoch==epochs: break
        err=[p-r['label'] for r,p in zip(train_rows,probs)]
        w=[v-lr*(sum(e*r['features'][j] for e,r in zip(err,train_rows))/n+l2*v) for j,v in enumerate(w)]
        bias-=lr*sum(err)/n
    return w,bias,history


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--dataset',type=Path,default=ROOT/'training/corpus/code-reference-v1.json')
    parser.add_argument('--output',type=Path,default=ROOT/'training/experiments')
    parser.add_argument('--deploy',action='store_true')
    args=parser.parse_args()
    started=time.perf_counter(); raw=args.dataset.read_bytes(); data=json.loads(raw)
    samples={s:{r['sample_sha256'] for r in data['rows'] if r['split']==s} for s in ('train','validation','test')}
    if any(samples[a]&samples[b] for a,b in [('train','validation'),('train','test'),('validation','test')]):
        raise ValueError('Sample leakage across splits')
    if any(len(r['features'])!=len(data['features']) or any(not math.isfinite(x) for x in r['features'])
           or r['label'] not in (0,1) for r in data['rows']): raise ValueError('Invalid dataset')
    config={'epochs':300,'learning_rate':0.3,'l2':0.01,'threshold':0.5,'initialization':'zeros','optimizer':'full-batch gradient descent'}
    w,bias,history=train(data,config['epochs'],config['learning_rate'],config['l2'])
    run_id=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out=args.output/run_id; out.mkdir(parents=True,exist_ok=False)
    model={'kind':'logistic-code-reference-ranker','feature_version':data['feature_version'],'features':data['features'],
           'weights':w,'bias':bias,'dataset_sha256':hashlib.sha256(raw).hexdigest(),'run_id':run_id,
           'not_a_malware_classifier':True,'slm_weights_updated':False}
    def save(name,value):
        (out/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    save('model.json',model); save('loss.json',history); save('config.json',config)
    result={'run_id':run_id,'kind':'actual-cpu-auxiliary-model-training','dataset_sha256':model['dataset_sha256'],
        'trainer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'feature_code_sha256':hashlib.sha256((ROOT/'vm_tools/code_search.py').read_bytes()).hexdigest(),
        'python':platform.python_version(),'platform':platform.platform(),'elapsed_s':round(time.perf_counter()-started,4),
        'model_sha256':hashlib.sha256((out/'model.json').read_bytes()).hexdigest(),
        'metrics':{s:metrics([r for r in data['rows'] if r['split']==s],w,bias) for s in samples},
        'human_reviewers':[], 'slm_finetuned':False,'hyperparameters_tuned_on_test':False,
        'limits':['117 structural anchors from 4 development samples; small and imbalanced',
                  'Labels are agent annotations, not human-reviewed malware ground truth',
                  'Test is sample-disjoint but NOT independent of prior project development',
                  'This does not establish lecturer acceptance of auxiliary training instead of SLM fine-tuning']}
    save('receipt.json',result)
    if args.deploy: (ROOT/'vm_tools/code_ranker.json').write_bytes((out/'model.json').read_bytes())
    print(json.dumps(result,ensure_ascii=False))


if __name__ == '__main__':
    main()
