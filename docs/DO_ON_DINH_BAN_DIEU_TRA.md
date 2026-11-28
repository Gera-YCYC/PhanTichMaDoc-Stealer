# Ba lượt điều tra Python trên cùng phiên bản

Hai báo cáo có thể cùng kết luận `suspicious` dù giữ các nhận định khác nhau. Để đo tiêu chí ổn định trên slide, nhóm so các nhận định mà người dùng thực sự thấy sau bước duyệt. Đáp án tĩnh 36 mục được dùng riêng để xác định những ý đúng còn bị bỏ sót.

## Cách xem khi demo

Mở web trên máy đã dựng lab, vào **Đánh giá → Độ ổn định của bản điều tra · ba lượt Python**. Mở **Đối chiếu từng mục của đáp án** để xem một mục được giữ, bị loại cùng câu chứa nó, hay mới chỉ xuất hiện trong dữ liệu đã đọc. Chọn một mã lượt trong **Lịch sử** để mở báo cáo và các vị trí trích dẫn. Màn hình tính số liệu từ biên bản của ba lượt thật. [Hướng dẫn khởi động](WEB_DIEU_TRA.md)

Trên máy còn giữ nhật ký, tại hàng **PY24-A09**, bấm **C7** ở cột lượt 1. Web mở đúng câu trong nhóm **Nhận định bị loại**. Bấm **Xem đoạn mã đã dẫn** để xem các dòng nguồn và SHA-256. Làm tương tự với **PY24-A26 → C2** ở lượt 2 rồi lượt 3 để xem cùng một mục được giữ và bị loại. Từng nút dùng ánh xạ giữa nhận định, lượt chạy và mục chấm. Trên máy mới chỉ có Git, bảng vẫn hiện đủ 36 mục. Nút mở nguồn xuất hiện khi máy có nhật ký tương ứng.

## Kết quả trên mẫu PythonStealer

| Lượt | Số câu giữ | Mục đúng / 36 | Precision | Recall | F1 | Lần gọi công cụ / Qwen | Thời gian |
|---|---:|---:|---:|---:|---:|---:|---:|
| [Lượt 1](../deliverables/real-demo-evidence/web-20261128T073934_730537f9.json) | 32 | 20 | 100% | 55,56% | 71,43% | 17 / 42 | 408,65 giây |
| [Lượt 2](../deliverables/real-demo-evidence/web-20261128T075603_72a10ec5.json) | 35 | 20 | 100% | 55,56% | 71,43% | 17 / 44 | 496,25 giây |
| [Lượt 3](../deliverables/real-demo-evidence/web-20261128T080428_c391512e.json) | 31 | 19 | 100% | 52,78% | 69,09% | 17 / 42 | 400,69 giây |

Có **28/40 nhận định trùng nhau qua ba lượt (70%)**, thấp hơn ngưỡng 80% của slide. Mỗi lượt gán verdict `suspicious` cho cùng mẫu có nhãn `malicious`, nên verdict khớp nhãn **0/3 lượt**. Precision trong bảng tính trên các ý đã đối chiếu với hồ sơ phát triển. Câu nằm ngoài phạm vi chấm được ghi riêng. Cả ba báo cáo vẫn thấp hơn ngưỡng recall 70% và F1 75%. [Biên bản tính lại theo từng mục](../deliverables/real-demo-evidence/staging-stability.json)

Cả bảy đường nối trên bản đồ có cùng trạng thái qua ba lượt. Ba đường có đủ bằng chứng tĩnh, bốn đường còn cần kiểm tra. Báo cáo giữ được 19 mục đáp án ở cả ba lượt. Một mục khác, A26, được giữ ở hai lượt đầu. Trong ca này, dẫn chứng xác nhận đối số tệp đính kèm liên hệ với kết quả tạo bản nén. Sự lặp lại của trạng thái sơ đồ chưa đủ để xác nhận dữ liệu nhạy cảm đã được gửi đi.

### Vì sao 16 mục bị bỏ sót cả ba lần?

| Quan sát lặp lại ở cả ba lượt | Số mục | Thay đổi cần kiểm bằng thí nghiệm tiếp theo |
|---|---:|---|
| Công cụ chưa lấy đủ các dòng nguồn cần cho nhận định | 7 | Khi nhận diện mắt xích thiếu, tìm lại điểm tạo và điểm dùng của dữ liệu. |
| Các dòng cần thiết đã được công cụ lấy về nhưng chưa từng có đủ trong một lần yêu cầu model tạo hoặc duyệt câu | 4 | Đưa các dòng chứng minh cùng một quan hệ vào cùng lần đọc, kèm vị trí và hash. |
| Đã có đủ dòng trong một lần yêu cầu nhưng báo cáo cuối thiếu ý tương ứng | 4 | Kiểm tra câu được đề xuất và quyết định duyệt theo từng ý. |
| Một ý có căn cứ xuất hiện trong câu bị loại | 1 | Tách mệnh đề rồi kiểm lại từng ý bằng đúng dòng nguồn. |

**Trường hợp A09.** Câu C7 có bằng chứng một trường dữ liệu được truyền vào hàm xử lý cục bộ, nhưng câu còn mô tả sai kiểu giá trị trả về. Cả ba lượt loại câu và mất A09. Sau khi đã chốt kết quả, nhóm bấm **Đọc lại phần có chứng cứ** ở lượt 1. Qwen được gọi thêm hai lần. Câu viết lại chỉ dẫn dòng 134–139 về truy cập cơ sở dữ liệu rồi lại bị loại. Các dòng đó chưa chứng minh việc truyền trường vào hàm. Nhật ký con `review_62cd4ee21387` ghi lần đọc này. Báo cáo gốc giữ nguyên và điểm bổ sung là 0 mục. [Tọa độ và hash nhật ký con](../deliverables/real-demo-evidence/web-20261128T073934_730537f9.json)

## Điều kiện của phép đo

- Lượt đầu là `20261128T073934_730537f9`. Hai lượt kế tiếp được ấn định trước khi bấm chạy thêm. Chương trình kiểm lại các nhật ký xen giữa. Cả ba dùng cùng SHA-256 của mẫu PythonStealer công khai, cùng digest Qwen3 8B, hash mã lõi, cấu hình suy luận và seed 42.
- Độ ổn định bằng số nhận định có mặt cả ba lượt chia cho số nhận định xuất hiện ít nhất một lần. Với hành vi, khóa đối chiếu là nguyên văn câu sau khi bỏ khoảng trắng hai đầu. Với IOC, dùng giá trị. Với ATT&CK, dùng mã kỹ thuật. Câu diễn đạt lại có thể làm giảm tỷ lệ này. Khi kế thừa **điểm** của câu, phép kiểm còn đòi trùng toàn bộ nội dung, loại, nguồn trích, tọa độ và từng byte trích dẫn sau khi chuẩn hóa mã lượt.
- Mỗi báo cáo được chấm riêng theo cùng đáp án. Với một câu vừa có ý đúng vừa có ý sai, giữ điểm từng ý khi đối chiếu và ghi lý do khi câu bị loại. Kết quả được duyệt từ mã và dữ liệu công cụ trên tập phát triển. Việc model tự đồng ý với một câu chưa tạo thành đáp án.
- Khi thiếu một mục, công cụ kiểm từng dòng tham chiếu trong kết quả VM và trong thông điệp thực gửi model để tạo hoặc duyệt ứng viên. Nhãn **Đủ dòng trong một lần hỏi model** chỉ xác nhận khả năng tiếp cận dữ liệu. Chưa thể suy ra model hiểu đúng các dòng đó.

## Cách kiểm lại

Trên máy chỉ có bản Git và môi trường Python, chạy lệnh sau để tính lại giao, hợp, P/R/F1 và bảng bỏ sót từ dữ liệu công khai.

```powershell
.\.venv\Scripts\python.exe -m eval.report_series
```

Trên máy còn giữ các nhật ký gốc, thêm `--replay` để kiểm cả chuỗi hash, báo cáo kết thúc, từng phép chấm, nội dung trích dẫn và các cửa sổ nguồn thực gửi cho Qwen. Trước khi tính độ ổn định, bộ kiểm xác nhận ba lượt khác nhau và mỗi lượt đã kết thúc. Để ghi lại các trích dẫn từ giao diện cho một lượt mới, mở web, thiết lập Chromium như trong hướng dẫn kiểm trình duyệt, rồi chạy `node scripts/verify_web_staging.mjs MA_LUOT --report`. [Thiết lập Chromium](DUONG_DAN_GHI_VA_NEN.md#ghi-bằng-chứng-thao-tác-trên-một-máy-khác)

Trên máy lưu ba lượt, chạy web bằng `scripts/Start-Web.ps1 -HistoryOnly`. Sau khi thiết lập Chromium, chạy `node scripts/verify_web_series.mjs` để mở A09 và A26 tại hai kích thước màn hình, đối chiếu từng dòng hiển thị với hồ sơ cục bộ. Kết quả được lưu ở `evidence/local/report-series-web.json`. Muốn tạo lượt mới bằng nút **Chạy điều tra**, khởi động web ở chế độ lab đầy đủ. [Hướng dẫn chạy](WEB_DIEU_TRA.md)
