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

## Chấm đủ câu thô trong thử nghiệm báo cáo đoạn

`claim_audit.py` kiểm SHA256 của report thô, yêu cầu có nhãn cho **mọi** ID, kiểm báo cáo sau lọc giữ đúng nội dung và chia đủ tập câu thô. Thiếu câu bị loại, đổi nội dung hoặc nhầm report đều gây lỗi; không được chỉ chấm tập câu tốt. File nhãn được lập qua đối chiếu source, không lấy quyết định supported của reviewer SLM làm đáp án.

```powershell
.\.venv\Scripts\python.exe eval/claim_audit.py runs/20261127T164056_2bc4e796 eval/adjudications/python2024-qwen3-cards-v1-full-audit.json --output evidence/local/card-claim-score.json
```

Run này đã chấm đủ 12 câu: 8 có căn cứ, 4 vượt quá chứng cứ; Precision/grounding trên **riêng tập câu của run này** là 8/12, hallucination là 4/12. Reviewer giữ 6 câu đúng và 3 câu thiếu căn cứ, đồng thời loại nhầm 2 câu đúng. [Kết quả](../deliverables/real-demo-evidence/python2024-cards-v1-claim-score.json).

Phép thử thành phần v2 trên 3 đoạn đã thu có 6/6 câu có căn cứ, nhưng reviewer loại nhầm 2 và verdict thiếu căn cứ gửi dữ liệu trong tập được giữ. [Kết quả riêng](../deliverables/real-demo-evidence/python2024-cards-v2-replay-score.json). Không so hai tập đoạn khác kích thước như một benchmark chung, không dùng phép thử thành phần thay demo VM.

Năm fact trong profile Python là các chuỗi thao tác tổng hợp, còn các câu model có độ chi tiết khác nhau. Vì chưa chốt và chấm đủ đơn vị đối chiếu, `claim_audit.py` để Recall/F1 là `null`. Không tăng Recall bằng cách viết nhiều câu đúng về cùng một thao tác ghi file. Khi có bảng đúng/sai/bịa/bỏ sót với đơn vị nhất quán, dùng `score.py` theo công thức giảng viên. Các bản chấm hiện tại là source audit tự động trên dữ liệu phát triển, chưa có người thật/GV phê duyệt và chưa đóng gate toàn corpus.
