# Quyết định về yêu cầu train

| Ngày | Quyết định / thông tin | Hệ quả |
|---|---|---|
| 27/11/2026 | Mốc 4 dùng Qwen2.5 Coder 7B Instruct pretrained qua Ollama | Đây là baseline inference, không là model do nhóm train |
| 27/11/2026 | Nhóm cho biết GV muốn xem quy trình train trên Git | Bổ sung hồ sơ training minh bạch |
| 27/11/2026 | Nhóm trả lời “Thầy chưa nói rõ” fine-tune SLM hay ML phụ trợ | Chưa chọn một cách train để tuyên bố đáp ứng GV |
| 27/11/2026 | Chuẩn bị QLoRA làm phương án nếu yêu cầu fine-tune SLM | Code/config ứng viên; chưa có GPU run hoặc adapter |

| 27/11/2026 | Train logistic ranker trên 117 anchor từ công cụ thật, lưu loss/config/checkpoint | ML phụ trợ phục vụ truy xuất; không tự thay yêu cầu SLM fine-tuning |

Các điểm GV chưa xác định (không chặn phát triển phần mềm):

1. Fine-tune SLM là bắt buộc, hay baseline pretrained + mô hình ML phụ trợ được chấp nhận?
2. Giảng viên đánh giá phần train qua dữ liệu/split/log/checkpoint/so sánh nào?
3. Có yêu cầu tối thiểu số mẫu hoặc giới hạn dữ liệu/hardware không?

Không tự suy diễn rằng ReAct yêu cầu fine-tuning; không suy diễn rằng một classifier phụ trợ có thể thay yêu cầu fine-tune SLM khi thầy chưa xác nhận.
