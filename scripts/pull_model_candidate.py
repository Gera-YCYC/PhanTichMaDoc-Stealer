"""Explicit local model comparison download; never replaces the default/Release."""
import json
from pathlib import Path
import sys
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
MODEL='qwen3:8b'
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
request=urllib.request.Request('http://127.0.0.1:11435/api/pull',
    data=json.dumps({'model':MODEL,'stream':True}).encode(),headers={'Content-Type':'application/json'})
out=ROOT/'evidence/local/model-download-qwen3-8b.jsonl'
last_status,last_pct='',-1
with opener.open(request,timeout=60) as response,out.open('a',encoding='utf-8') as log:
    for line in response:
        row=json.loads(line); row['recorded_epoch']=time.time()
        log.write(json.dumps(row)+'\n'); log.flush()
        if 'error' in row: raise RuntimeError(row['error'])
        status=row.get('status',''); pct=int(100*row.get('completed',0)/row['total']) if row.get('total') else -1
        if status!=last_status or pct>=last_pct+10:
            print(json.dumps({'model':MODEL,'status':status,'percent':pct,'bytes':row.get('total')}),flush=True)
            last_status,last_pct=status,pct
print('Candidate downloaded; baseline/default/Release unchanged',flush=True)
