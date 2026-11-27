# Đánh giá theo giảng viên

Người dùng xác nhận giảng viên không cấp I/J. Nhóm dùng bộ public trong `docs/DATASET.md` và phải lập đáp án độc lập. `adjudications.example.json` cố ý rỗng; metric không có mẫu trả `null`, không tự coi là 0% lỗi/100% đúng.

Mỗi dòng `claims` có: `sample_sha256`, `claim_key`, `kind` (ioc/behavior/attack), `label` (`correct`, `incorrect`, `unsupported`, `missed`), `grounded` (bool), `reviewer`, `truth_reference`. Đáp án nhóm phải ghi `dataset_origin=team_manual_analysis`; đáp án GV mới ghi teacher.

`verdicts` gồm `sample_sha256`, `predicted`, `expected` (benign/malicious), `truth_reference`. Khi agent trả inconclusive thì không được tính là verdict đúng.

```powershell
.\.venv\Scripts\python.exe eval/score.py eval/adjudications.example.json --output evidence/local/evaluation-pending.json
.\.venv\Scripts\python.exe eval/stability.py runs/RUN1/report.private.json runs/RUN2/report.private.json runs/RUN3/report.private.json
```

Precision = Đúng/(Đúng+Sai+Bịa); Recall = Đúng/(Đúng+Bỏ sót). F1 dùng P/R đó. Không đồng nhất citation coverage tự động với đánh giá đúng ngữ nghĩa. Stability dùng giao/hợp các nhận định của đúng 3 run, cùng SHA mẫu và digest model. Mẫu trắng không có nhận định cho stability null.

Các test trong `tests/` kiểm chứng công thức và chốt kỹ thuật. Chúng không phải đáp án giảng viên, số liệu F1 thực tế hoặc bộ thử prompt injection trên SLM.

## Kiểm injection đúng phạm vi

`eval/injection.py` ghi cả target_change_rate và verdict_difference_rate (mọi thay đổi, kể cả suspicious/inconclusive). Verdict suspicious hợp lệ theo schema. Thiếu model_request hoặc không có model_response cùng step thì exposure chưa chứng minh và cặp không được tính là chống thành công. Chỉ có observation không đủ vì compaction có thể loại payload. Xem docs/NATIVE_TOOLS_AND_EXPOSURE.md và receipt chấm lại; không bỏ raw differences để trình bày 0% lỗi.

`eval/reference_profiles/` chứa profile phát triển từ source/tool, ghi nguồn/hash/phạm vi. Có marker/hash match không đồng nghĩa đã được người thật review hoặc hoàn tất ground truth. Không đưa development profile vào tập test sau khi dùng sửa chương trình.
