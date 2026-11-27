# Giao thức dữ liệu fine-tuning dự kiến

Corpus chưa có record được nhóm duyệt. Năm mẫu đã tải là tập ứng viên phân tích, không tự trở thành dữ liệu train có nhãn.

## Record JSONL

Mỗi dòng là tình huống chọn action hoặc lập báo cáo có chứng cứ, không phải binary mẫu:

- id: mã duy nhất.
- sample_sha256: SHA256 mẫu đã xác minh trong VM.
- family_id: nhóm family/nguồn dùng chia tập; không đổi tên để lọt kiểm leakage.
- source_evidence: danh sách artifact_sha256, line_start, line_end trỏ chứng cứ tool.
- prompt_messages: system/user messages kết thúc bằng user; đặc trưng đã duyệt và mô tả nhiệm vụ.
- completion: action JSON theo stealer_agent/contracts.py, do người phân tích chỉnh/duyệt.
- review: approved=true, reviewers có ít nhất hai người khác nhau, redacted=true, synthetic=false.

Không có record mẫu giả trong corpus. Unit tests dùng record tổng hợp để thử validator, tách khỏi corpus/experiments và không tính vào số train record.

## Thu thập và duyệt

1. Tool chạy trong VM, lấy đặc trưng/chứng cứ; không đưa binary vào training.
2. TV1/TV2 phân tích độc lập để xác định action/report mục tiêu; không copy nhãn từ SLM chưa kiểm.
3. TV4 đối chiếu, loại claim thiếu căn cứ; unresolved ghi inconclusive khi phù hợp.
4. Che webhook/token/PII trước khi xuất dataset; giữ raw evidence riêng trong VM.
5. Hai reviewer ký trạng thái. Validator kiểm metadata/schema/candidate secrets, không tự xác minh chất lượng nhãn.

## Tách tập

Tạo train.jsonl, validation.jsonl, test.jsonl tại private/training-data. Chia theo sample/family trước khi sinh nhiều record. Mọi record cùng sample/family phải cùng tập, không random từng dòng để cùng file/family xuất hiện cả train/test.

Validator chặn id trùng, sample/family qua tập, prompt trùng qua tập, thiếu review và chuỗi dạng token. Chưa kiểm near-duplicate hoặc contamination từ upstream; nhóm phải nêu giới hạn.

Tỉ lệ dự kiến70/15/15 chỉ dùng khi đủ nhóm độc lập; không ép năm mẫu thành ba tập rồi tuyên bố đủ đánh giá. Công bố số group/file/record thực và lý do chọn quy mô. Chưa có ngưỡng số lượng do GV xác nhận.

Validation chọn hyperparameter; test khóa trước và chỉ dùng sau chốt, không đưa vào Trainer. Bổ sung file sạch, thiếu chứng cứ, lỗi tool và injection để tránh chỉ học kết luận malicious.

## Chia sẻ

Dataset đặc trưng được review/che bí mật có thể đưa Git hoặc Release. Nếu không thể công khai, công bố manifest/hash/protocol và cung cấp bản được phép cho GV. Không tuyên bố tái lập đầy đủ khi dữ liệu chưa cung cấp.
