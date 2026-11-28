# Kiểm từng ý trong nhận định bị loại

Khi một câu gộp lời gọi hàm, kiểu dữ liệu và kết quả trả về, người phân tích có thể kiểm từng ý ngay trên báo cáo. Phép thử trên bảy câu thật tìm được ít nhất một ý đúng ở **4/7 câu gốc**, so với **2/7** khi yêu cầu Qwen viết lại một câu. Đổi lại, Qwen cũng chấp nhận nhiều ý thiếu bằng chứng hơn. Nhóm giữ chức năng này ở màn hình kiểm tra của người phân tích.

## Demo trực tiếp

1. Khởi động lab bằng `.\scripts\Start-Web.ps1`. Mở web tại `http://127.0.0.1:4180`. Chọn lượt Python `20261128T073934_730537f9` trên máy đã chạy, hoặc chọn một lượt mới có nhận định hành vi bị loại.
2. Mở **Nhận định → Nhận định bị loại → C7 → Tách và kiểm từng ý**. Trên máy lab của nhóm cũng có thể đi từ **Đánh giá → Độ ổn định của bản điều tra · ba lượt Python → PY24-A09 → C7**.
3. Mở riêng từng ý rồi chọn **Xem đoạn mã đã dẫn**. Trong lượt đo trên C7, một ý mô tả đúng chữ ký hàm. Một ý khác nói đến 12 byte đầu nhưng dòng nguồn dùng khoảng `[3, 15)`. Giao diện đánh dấu mâu thuẫn và hiển thị quyết định ban đầu của Qwen. Với khoảng có cận là biến hoặc nhiều câu lệnh cùng dòng, bộ kiểm cú pháp này chưa đưa ra nhận xét.
4. Chuyển sang Gomorrah, lượt `20261128T030521_c76fc69a`, mở **C5**. Ở đây Qwen giữ ý có dẫn chứng về cách ghép đối số đích và loại ý suy đoán nội dung tệp. Cũng có một ý được Qwen giữ dù thiếu dòng ghép phần cơ sở của địa chỉ. Khi nhóm mở lại hai hồ sơ trên trình duyệt ở chiều rộng 390 px, cả bảy trích dẫn của hai lần thử đều dẫn về đúng các dòng đã lưu.
5. Để xem trên máy chỉ có Git, mở web với `-HistoryOnly`, vào **Đánh giá → Đối chiếu từng ý trong bảy câu bị loại**. Trên máy đã dựng lab, **Tắt lab** sau khi tác vụ cuối hoàn tất. [Cài máy thành viên](TEAM_SETUP.md) · [Kết quả và tọa độ trích dẫn](../deliverables/real-demo-evidence/split-review.json)

## Cách tạo và duyệt

Qwen3 8B nhận câu bị loại và các đoạn trích đã được công cụ trong VM trả về. Mô hình đề xuất tối đa ba ý. Mỗi ý chọn tối đa sáu dòng có sẵn thuộc cùng một nguồn. Chương trình kiểm tọa độ và giới hạn của trích dẫn. Mỗi lượt duyệt tiếp theo chỉ nhận một ý và phần nguồn dành riêng cho ý đó. Câu trả lời của một ý không xuất hiện trong yêu cầu duyệt ý kế tiếp.

Giao diện phân biệt quyết định của Qwen với điểm cần người đọc kiểm lại. Đối với mô tả rõ số byte đầu, Python AST có thể đối chiếu với cận của đúng phép cắt đã dẫn. Kiểm tra này yêu cầu một phép gán, biến đích trùng với chủ thể trong câu, cận nguyên cố định và một dòng Python. Đây là kiểm tra số học hẹp. Các khẳng định về kiểu, nguồn gốc của tệp và quan hệ giữa hai biến vẫn cần đối chiếu riêng.

Hồ sơ gốc giữ nguyên. Lần đọc bổ sung có mã riêng trong `runs/<lượt>/parts-reviews/<mã>/events.jsonl`. Từ hồ sơ này có thể truy ngược tới hash nhật ký ban đầu, câu nguồn và hai phía của từng lần gọi model. Lần đọc bổ sung sử dụng lại các trích dẫn VM đã thu. [Luồng hỏi đáp khi cần tìm thêm trong VM](WEB_DIEU_TRA.md)

## So sánh trên cùng bảy câu

Chọn toàn bộ câu hành vi bị loại đủ điều kiện trong ba lượt đã chốt, gồm một câu Python và sáu câu .NET. Nhánh đối chứng dùng các lần đọc một câu đã ghi trước đó, với cùng hash yêu cầu nguồn cho từng câu và cùng digest model. Nhóm chấm lại theo nội dung trích dẫn của từng ý. Bảng là kết quả phát triển trên ba mẫu từng dùng để nghiên cứu.

| Cách đọc | Ý được duyệt | Ý giữ | Giữ và đúng | Giữ nhưng sai | Giữ dù thiếu căn cứ | Câu gốc có ít nhất một ý đúng được giữ |
|---|---:|---:|---:|---:|---:|---:|
| Viết lại một câu | 7 | 3 | 2 | 0 | 1 | 2/7 |
| Tách và duyệt từng ý | 21 | 15 | 6 | 2 | 7 | 4/7 |
| Sau khi gạt riêng mâu thuẫn khoảng chỉ số | 21 | 14 | 6 | 1 | 7 | 4/7 |

Nhánh một câu dùng 14 lần gọi, 12.559 token vào, 963 token ra và 97,65 giây suy luận. Nhánh tách ý dùng 28 lần gọi, 11.805 token vào, 2.014 token ra và 272,92 giây suy luận. Hai thao tác bấm web kiểm chứng dùng thêm tám lần gọi ngoài bảng. Kết quả của cả hai lần bấm khớp thí nghiệm về nội dung, tọa độ và quyết định của từng ý.

Mục **A09** vẫn thiếu trong lần đọc này. Chữ ký và các dòng trong thân hàm chưa đủ để xác nhận trường nào ở phía gọi được truyền vào hàm. Muốn cải thiện recall cần kiểm cả vị trí lấy trường và đối số thật tại điểm gọi, rồi đánh giá trên báo cáo kết thúc và trên mẫu giữ riêng. Hiện nhóm chưa đưa các ý đọc bổ sung vào verdict. [Nhãn từng ý và lý do](../eval/adjudications/parts-review.json) · [Điểm toàn báo cáo Python](DO_ON_DINH_BAN_DIEU_TRA.md)

## Tái lập

Trong **Đánh giá**, chọn mẫu rồi mở **Đối chiếu từng ý trong bảy câu bị loại → Xem từng nhận định**. Bảng đặt câu agent nói, trích dẫn, quyết định của Qwen và lý do chấm cạnh nhau. Với A09, nhật ký xác nhận yêu cầu duyệt gốc có đủ 13 dòng tham chiếu. Ba ý tách ra chỉ chọn dòng 69, 70 và 72. Các dòng 140–144 ở phía gọi đã có sẵn khi duyệt câu gốc nhưng bị bỏ qua lúc chọn dẫn chứng. Biên bản tái lập kiểm cả văn bản lẫn tọa độ của 13 dòng đó trước khi tính số.

- Từ bản Git, chạy `python -m eval.parts_audit` để tính lại ba hàng từ biên bản và nhãn.
- Trên máy có các nhật ký gốc, chạy `python -m eval.parts_audit --replay` để dựng lại từng yêu cầu và trích dẫn, cả ở thí nghiệm và hai lượt web. Bộ kiểm còn đối chiếu các dòng đã mở trong trình duyệt.
- Để chạy suy luận mới trên cùng bộ đầu vào, bật Ollama dự án bằng `.\scripts\Start-LocalModel.ps1 -PromptCacheMiB 0`, chạy `python -m eval.parts_trial` rồi dừng bằng `.\scripts\Stop-LocalModel.ps1`. Mỗi thí nghiệm có thư mục thời gian riêng. Đối chiếu nguồn trước khi gán nhãn cho kết quả mới.
- Trên máy lab đã mở web và thiết lập Chromium, chạy `node scripts/verify_web_parts.mjs MA_LUOT C7` để bấm thật và mở lại từng trích dẫn. [Thiết lập trình duyệt](DUONG_DAN_GHI_VA_NEN.md#ghi-bằng-chứng-thao-tác-trên-một-máy-khác)
