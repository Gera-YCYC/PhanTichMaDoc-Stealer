# Ghi chú API và kiểm định bộ tự duyệt

## Vì sao bổ sung

Đối chiếu v4 ghi nhận hai loại lỗi khác nhau: thiếu chứng cứ từ thân helper, và hiểu sai thao tác đã có đủ câu lệnh. Nhóm thứ hai gồm nhầm response bytes của WebClient.UploadFile thành file gửi đi, hoặc gọi ASCII GetString là giải mã mật mã. Kéo dài source không tự sửa hiểu sai API.

`stealer_agent/api_reference.py` chứa tập ghi chú ngắn, cố định, dùng offline khi chạy model. Mỗi mục có ID, nội dung và URL nguồn chính thức; tập mục được chọn có version/hash ghi trong journal. Không có hash mẫu, nhãn family hay đáp án cho từng file.

Các nguồn: [WebClient.UploadFile](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.uploadfile?view=net-10.0), [ASCIIEncoding.GetString](https://learn.microsoft.com/en-us/dotnet/api/system.text.asciiencoding.getstring?view=net-10.0), [NewLateBinding.LateGet](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.compilerservices.newlatebinding.lateget?view=net-10.0), [sqlite3](https://docs.python.org/3/library/sqlite3.html), [smtplib](https://docs.python.org/3/library/smtplib.html). Chúng định nghĩa ý nghĩa thư viện, không chứng minh binding hay hành vi của mẫu.

## Ranh giới thực thi

Controller chọn ghi chú theo từ xuất hiện trong excerpt, đưa cùng ghi chú cố định vào system prompt của bộ sinh câu và bộ kiểm câu. Source vẫn nằm trong vùng dữ liệu không tin cậy. Hàm chọn không nối bất kỳ đoạn source nào vào system prompt. Một tên API nằm trong comment/string cũng có thể làm ghi chú được chọn; vì vậy kết quả chọn ghi chú không bao giờ được xem như phát hiện một lời gọi.

Mẫu vẫn ở VM. Host chỉ dùng các đoạn đã nhận từ công cụ, không mở binary hay gửi source lên dịch vụ đám mây. Phiên bản báo cáo ghi `evidence-cards/5`, nhưng wire config vẫn `evidence-cards-v1` để tương thích. Tập ghi chú là tài liệu hỗ trợ inference, **không phải huấn luyện hay cập nhật trọng số SLM**.

## Thực nghiệm phải phân biệt

- `scripts/replay_card_report.py`: sinh báo cáo mới bằng SLM thật từ các đoạn VM đã lưu. Cờ `--no-api-guidance` bỏ ghi chú API; prompt v5, source, model và seed vẫn giữ. Không gọi lại tool, không phải demo ReAct end-to-end.
- `scripts/replay_claim_review.py`: giữ nguyên từng câu và citation từ report cũ để đo riêng quyết định của reviewer. Nhãn audit chỉ được đọc **sau** các response, không nằm trong prompt. `--decision-first` đổi thứ tự schema, `--limit` chỉ dùng cho smoke có ghi rõ số câu/tổng câu; không được báo kết quả tập con thành cả report.
- Một lần đầy đủ cần chạy agent trong VM với source/config chốt, sau đó chấm lại toàn bộ câu thô. Tỷ lệ câu được giữ không phải Precision và không thay được kiểm nội dung.

## Kết quả đã quan sát trước khi chốt

Ba card .NET trong hai phép thử v5 có cùng hash nội dung và khớp ba card đầu của v4. Ghi chú giúp model mô tả một thao tác GetString thành chuyển phản hồi sang text, nhưng reviewer còn có lý do tự mâu thuẫn với cờ boolean. Không coi thêm ghi chú là đã sửa toàn bộ bộ duyệt.

[Phép thử cố định 19 câu với đánh giá trước quyết định](../deliverables/real-demo-evidence/critic-v5-assessment-first.json): giữ đúng 3 câu, loại nhầm 4 câu đúng, giữ 8 câu sai/thiếu căn cứ, loại đúng 4 câu sai/thiếu căn cứ. Do đó chưa được tin bộ tự duyệt để cấp nhãn đúng hoặc đóng gate TRUST. Nhãn đối chiếu là source audit phát triển, chưa có người thật/GV phê duyệt. Receipt đầu này chưa ghi riêng trường think trong settings; cấu hình dùng cho lệnh là candidate không suy luận. Các phép thử tiếp theo khóa cả think và config SHA256 để tránh thiếu provenance.

[Smoke chế độ suy luận](../deliverables/real-demo-evidence/critic-v5-thinking-smoke.json) đã hoàn tất với đúng ba câu đầu trong tập 19 câu cố định: model giữ cả ba, trong đó hai câu đúng và một câu thiếu căn cứ theo source audit. Thời gian 237,299 giây, 4.880 prompt token và 2.146 completion token. Đây chỉ là tập con và không có đối chứng đủ để quy cải thiện cho thứ tự schema hoặc chế độ suy luận. Không đổi mặc định model/think hoặc Release. Kết quả âm được giữ cùng mẫu số và cấu hình.

Hướng tiếp theo là bổ sung dữ kiện API có vai trò đối số/kết quả từ parser trong VM. Chúng được ghi riêng trong `typed_operations`, chưa thay thế nhận định SLM, chưa chứng minh quan hệ thu thập → gửi dữ liệu và chưa đóng gate chất lượng. Xem [thiết kế và giới hạn](TYPED_OPERATIONS.md).
