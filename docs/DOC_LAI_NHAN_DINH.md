# Đọc lại phần có chứng cứ trong một nhận định bị loại

Một câu có thể mô tả đúng lời gọi hàm nhưng đoán sai dữ liệu đi qua hàm đó. Người phân tích có thể yêu cầu Qwen thử giữ phần kiểm tra được, mở các dòng mô hình đã chọn và tự đối chiếu. Báo cáo gốc và kết quả chấm của lượt điều tra được bảo toàn.

## Trình diễn trên máy lab

1. Từ PowerShell ở thư mục dự án, chạy `.\scripts\Start-Web.ps1`. Mở `http://127.0.0.1:4180`. Máy Windows phục vụ web và chạy Qwen3 8B. VM cô lập giữ mẫu và cung cấp các công cụ phân tích tĩnh. [Cài máy nhóm và chuẩn bị VM](TEAM_SETUP.md)
2. Chọn một lượt thật đã chạy trên máy hoặc chạy một cuộc điều tra mới. Mở **Nhận định → Nhận định bị loại**, chọn một câu hành vi có trích dẫn và yêu cầu duyệt gốc hợp lệ.
3. Bấm **Đọc lại phần có chứng cứ**. Một lần gọi Qwen chọn tối đa sáu dòng và đề xuất một câu. Khi các dòng hợp lệ, lần gọi Qwen thứ hai chỉ duyệt câu mới trên phần nguồn đó. Bấm trích dẫn để đối chiếu. Thao tác này dùng nguồn VM đã thu. Muốn tìm thêm mã trong VM, dùng phần hỏi đáp điều tra. [Cách chạy điều tra trực tiếp](WEB_DIEU_TRA.md)
4. Mở lại hồ sơ để kiểm tra lịch sử. Mỗi lần bấm có nhật ký riêng ở `runs/<lượt>/claim-reviews/<mã đọc lại>/events.jsonl`, gắn với hash nhật ký gốc, hash mẫu và digest model. Chọn **Tắt lab** sau buổi demo.

Trong bản clone mới, vào **Đánh giá → Đọc lại phần có chứng cứ trong câu bị loại** để xem kết quả công bố. Danh sách lượt điều tra trên máy sẽ có dữ liệu sau khi nhóm chạy lab. Nhật ký riêng có trích đoạn nguồn được giữ tại máy thực hiện.

## Hai trường hợp nên mở cạnh nhau khi vấn đáp

| Mẫu và lượt web tại máy lab | Qwen đã chọn | Đối chiếu với nguồn |
|---|---|---|
| Mercurial · `20261128T031606_ca91de35` · C8 | Dòng 667 và 668 | Dòng đầu xác định đối tượng, dòng sau cho thấy lời gọi với năm vị trí đối số, trong đó vị trí thứ ba là `null`. Nhận định hẹp về lời gọi có đủ chứng cứ. |
| Gomorrah · `20261128T030521_c76fc69a` · C5 | Dòng 3677, 3678 và 3681 | Các dòng cho thấy cách ghép đích, tạo đối tượng và gọi hàm gửi với một đường dẫn. Qwen còn gọi nội dung tệp là ảnh chụp màn hình. Muốn xác nhận chi tiết đó phải tìm nơi tạo hoặc ghi nội dung vào cùng tệp. |

Qwen giữ cả hai câu. Trong hai lần bấm thật, kết quả khớp đúng câu tương ứng của thí nghiệm bên dưới. Mỗi lần dùng hai yêu cầu model. Đã mở lại được cả hai và so SHA-256 báo cáo trước/sau. Cả hai hash báo cáo giữ nguyên. [Biên bản tương tác thực](../deliverables/real-demo-evidence/web-narrow-interaction.json)

## So hai cách dẫn nguồn trên cùng 13 câu

Nhóm lấy 13 câu hành vi bị loại từ sáu nhật ký thuộc bốn mẫu phát triển. Trong đó có ba lượt web gốc, hai lần lấy thêm đoạn .NET và một hồ sơ AgentTesla. Dữ liệu đưa vào từng nhánh bắt đầu từ cùng câu, cùng yêu cầu duyệt và cùng chứng cứ VM. Cả hai dùng cùng digest Qwen3 8B. Nhóm đối chiếu từng câu viết lại với đúng các dòng nó trích, kể cả những câu bộ duyệt loại. Đây là nhãn phát triển của dự án.

| Cách đề xuất | Đủ điều kiện | Có câu và trích dẫn để duyệt | Qwen giữ | Giữ và đúng | Giữ dù thiếu căn cứ | Đúng nhưng bị loại | Lượt gọi model | Token vào / ra | Giây |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Chọn khoảng dòng | 13 | 6 | 2 | 1 | 1 | 1 | 19 | 17.383 / 1.568 | 186,645 |
| Chọn từng dòng có sẵn | 13 | 13 | 7 | 2 | 5 | 1 | 26 | 22.812 / 1.813 | 213,375 |

Ở cách thứ nhất, sáu đề xuất trích sai khoảng và một đề xuất lặp lại nguyên câu. Cách thứ hai cho phép duyệt đủ 13 câu, nhưng bộ duyệt đã chấp nhận năm câu thiếu chứng cứ. Cả chỉ dẫn cho model và cách chọn dòng đều thay đổi giữa hai nhánh. Phép thử đo tác động của cả hai thay đổi trên bộ phát triển này. Tổng cộng hai thí nghiệm có 45 lượt gọi model, ngoài bốn lượt gọi trong hai tương tác web trên. [Bảng chấm từng câu](../deliverables/real-demo-evidence/web-narrow-review.json) · [Nhãn và lý do đối chiếu](../eval/adjudications/narrow-claims.json)

Các đề xuất được giữ ở phần đọc lại tự chọn. Điểm ba báo cáo gốc vẫn là precision 89,74%, recall 36,08%, F1 51,47%, verdict đúng 0/3 theo nhãn lành/độc đã chốt. Kết quả trên cho thấy giá trị của việc mở trích dẫn khi vấn đáp và giới hạn của việc dùng cùng một model để tự duyệt. Bước cần đo tiếp là khả năng truy vấn VM tìm những dòng nguồn còn thiếu, sau đó chấm kết quả trên tập tách riêng. [Bảng điểm và vị trí bỏ sót](CHAM_BA_MAU_WEB.md)

## Kiểm tra và tái lập

Ở thư mục dự án, với môi trường Python của dự án đã kích hoạt, mọi thành viên có thể kiểm tra bảng công bố bằng `python -m eval.narrow_audit`. Máy còn giữ nhật ký gốc của hai thí nghiệm có thể chạy `python -m eval.narrow_audit --replay` để dựng lại từng yêu cầu, câu trả lời, trích dẫn và kết quả đối chiếu. Hai lệnh này chạy ngoại tuyến.

Trên máy lab có đủ sáu nhật ký nguồn của bộ phát triển, chạy suy luận mới như sau. Lượt mới có mã thời gian riêng. Đối chiếu câu trả lời mới với nguồn trước khi gán nhãn.

```powershell
.\scripts\Start-LocalModel.ps1 -PromptCacheMiB 0
try {
    python -m eval.narrow_trial --mode ranges
    if ($LASTEXITCODE -ne 0) { throw "Lỗi khi thử chọn khoảng dòng" }
    python -m eval.narrow_trial --mode lines
    if ($LASTEXITCODE -ne 0) { throw "Lỗi khi thử chọn từng dòng" }
} finally {
    .\scripts\Stop-LocalModel.ps1
}
```
