# Che thông tin đăng nhập trong bản xem báo cáo

## Vấn đề đã quan sát

Trong run Python v4, source được dẫn có thông tin SMTP hardcode và một câu model viết nhắc lại literal đó. Bộ che cũ chỉ biết mẫu Discord webhook/Telegram token, nên tên `report.redacted.json` không có nghĩa mọi thông tin đăng nhập đã được che. Không đưa giá trị thật vào tài liệu hay test.

## Thay đổi

`stealer_agent/redaction.py` thu các literal được gán vào tên biến/trường nhạy cảm (password, token, secret, username, API key...), và hai đối số literal trong lời gọi login/authenticate. Đầu vào là những dòng đặc trưng/excerpt đã được controller nhận từ VM và các chuỗi trong báo cáo. Không mở mẫu từ host, không gọi mạng, không thực thi source. Chỉ `ast.literal_eval` một string literal đã khớp mẫu và bị giới hạn kích thước.

Các giá trị nhận diện được che lại trong mọi trường chuỗi của bản xem, gồm lời nhận xét model/reviewer và citation. Email và các pattern Discord/Telegram cũ tiếp tục được che. Xử lý trên từng giá trị chuỗi trước khi serialize, tránh làm hỏng escape/JSON. Không sửa input model, `report.model-raw.json`, `report.private.json` hoặc `events.jsonl`.

`redaction.public_export_approved=false` luôn được ghi vào bản xem. Citation sau che là bản hiển thị; việc kiểm hash/quote dùng bản riêng tư nguyên gốc. Receipt công khai vẫn loại toàn bộ prose/source, chỉ chọn metadata định trước bằng `scripts/report_experiment_receipt.py`.

## Kiểm chứng và phạm vi

Sáu test mới dùng literal vô hại để kiểm: secret được lặp lại ở prose, context thiếu trong citation cuối, login/dictionary, Unicode/quote/backslash và JSON, pattern cũ, giới hạn scan, giữ nguyên report gốc. Toàn bộ bộ kiểm thử đạt 137 ca trên Windows tại bản này; không phải số mẫu malware.

[Kiểm trên hai report thật lưu sẵn](../deliverables/real-demo-evidence/report-redaction-v1-check.json) xác nhận hai literal nhận diện của Python đều bị che; .NET không có literal khớp rule này. Hash report gốc không đổi. Kiểm này không chạy lại model/tool và không chứng minh .NET không có credential. Bản render kiểm riêng nằm cục bộ dưới `private/report-experiments/redaction-v1/`.

```powershell
.\.venv\Scripts\python.exe scripts/verify_report_redaction.py --run <run-id> --output evidence/local/redaction-check.json
```

Để giới hạn tài nguyên, scan tối đa 512.000 ký tự mỗi chuỗi và tổng 8.000.000 ký tự; literal tối đa 8.192 ký tự. Nếu vượt giới hạn, metadata ghi `scan_truncated=true`. Secret nằm trong biểu thức ghép/giải mã, alias, tên không nhận diện hoặc cú pháp ngoài các pattern có thể chưa bị che. Không dùng checker này để phê duyệt tự động một bản raw cho Git.
