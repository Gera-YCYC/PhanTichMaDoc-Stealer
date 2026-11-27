"""Prepare a human review worksheet from raw claims; never invent labels or truth."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from stealer_agent.journal import dump_json
from stealer_agent.security import redact

root=Path(__file__).resolve().parents[1]
batch=json.loads((root/'evidence/local/milestone4-latest.json').read_text(encoding='utf-8-sig'))
final=root/'evidence/local/final-validation.json'
if final.is_file():
    batch['runs'].extend(json.loads(final.read_text(encoding='utf-8-sig'))['runs'])
rows=[]
for item in batch['runs']:
    directory=root/'runs'/item['run_id']
    raw_path=directory/'report.model-raw.json'
    if not raw_path.is_file():
        continue
    raw=json.loads(raw_path.read_text(encoding='utf-8'))
    for claim in raw['claims']:
        rows.append({'run_id':item['run_id'],'sample':item['sample'],'sample_sha256':item['sample_sha256'],
                     'claim_id':claim['id'],'claim_key':claim['text'],'kind':claim['kind'],
                     'agent_claim':claim,'label':None,'grounded':None,'reviewer':'','truth_reference':''})
pending={'dataset_origin':'pending_team_review_mixed_fixture_and_public_separate_before_scoring',
         'status':'worksheet_only_not_scored','claims':rows,'missed_ground_truth_items':[],
         'instructions':'Score raw claims including rejected claims. Separate fixtures from public malware. Add independently discovered missed items. Fill reviewer and truth_reference before scoring.'}
dump_json(root/'eval/review-worksheet.json',json.loads(redact(json.dumps(pending,ensure_ascii=False))))
lines=['# Phiếu kiểm nhận định từ các run buổi 4','',
       'Phiếu này chưa chấm. Nhóm kiểm chứng độc lập từng câu, kể cả câu reviewer đã loại. '
       'Tách fixture khỏi malware public và bổ sung mục bỏ sót trước khi tính P/R/F1.','',
       '| Run / mẫu | Agent nói | Dẫn chứng agent chọn | Thực tế / nhãn / người chấm |',
       '|---|---|---|---|']
for row in rows:
    c=row['agent_claim']; refs='; '.join(f"{e['evidence_id']}:{e['line']} — {e['quote']}" for e in c['evidence'])
    esc=lambda s: str(s).replace('|','\\|').replace('\n',' ')
    lines.append(f"| {esc(row['run_id'])}<br>{esc(row['sample'])} | {esc(c['text'])} | {esc(refs)} | Chưa chấm |")
lines+=['','JSON để điền có cấu trúc: `eval/review-worksheet.json`. Không chạy score.py trực tiếp với phiếu chưa có nhãn.',
        'Nguồn ground truth phải độc lập với chính output của agent. Log công cụ kiểm định dạng được, nhưng muốn xác nhận hành vi phải đọc code/luồng dữ liệu hoặc nguồn phân tích tương ứng.']
(root/'docs/PHIEU_DANH_GIA.md').write_text(redact('\n'.join(lines))+'\n',encoding='utf-8')
print(json.dumps({'ungraded_claims':len(rows)}))
