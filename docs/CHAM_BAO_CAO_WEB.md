# Chấm ba lượt web trên cùng mẫu Python

Trên web, mở **Đánh giá**. Bảng đầu cho biết báo cáo phủ bao nhiêu mục trước và sau khi agent tự duyệt. Mở **Đối chiếu từng câu** để xem nhận định, dòng nguồn, nhãn chấm và quyết định giữ hoặc loại. Mở **Mục còn thiếu** để truy lại phần đáp án bị bỏ sót. Ba lượt dùng cùng mẫu PythonStealer, Qwen3 8B, phiên bản agent và cấu hình. [Biên bản nhận dạng ba lượt](../deliverables/real-demo-evidence/web-stability-python.json)

## Kết quả so với slide

| Lượt | Câu đầu → giữ | Mục đúng đầu → sau, trên 36 | Precision đầu → sau | Recall đầu → sau | F1 đầu → sau |
|---|---:|---:|---:|---:|---:|
| [bec5b2e5](../deliverables/real-demo-evidence/web-python-quality/20261128T021511_bec5b2e5/review.md) | 30 → 29 | 20 → 19 | 95,24% → 100% | 55,56% → 52,78% | 70,18% → 69,09% |
| [4014e541](../deliverables/real-demo-evidence/web-python-quality/20261128T022955_4014e541/review.md) | 30 → 30 | 20 → 20 | 95,24% → 95,24% | 55,56% → 55,56% | 70,18% → 70,18% |
| [4ad0f5f6](../deliverables/real-demo-evidence/web-python-quality/20261128T023637_4ad0f5f6/review.md) | 39 → 36 | 20 → 19 | 80% → 86,36% | 55,56% → 52,78% | 65,57% → 65,52% |

Sau tự duyệt, cả ba đạt mục tiêu precision 80%. Cả ba còn dưới mục tiêu recall 70% và F1 75%. Chấm riêng IOC và ATT&CK theo rubric cho F1 66,67% ở cả sáu hàng, với 2/4 mục tham chiếu được nêu đúng. Verdict của cả ba là `suspicious` trong khi nhãn tham chiếu của mẫu là `malicious`. Độ ổn định nguyên nhận định là 27/38 (71,05%) so với yêu cầu 80%. [Chỉ tiêu của giảng viên](YEU_CAU_GIANG_VIEN.md)

Đáp án phát triển gồm 36 đơn vị hành vi, IOC và ATT&CK đã chốt trước ba lượt web. Phép tính giữ một lần đếm cho mỗi đơn vị trùng lặp. Phát hiện đúng ngoài phạm vi được ghi riêng. Bảng từng câu bao phủ cả 99 lần xuất hiện, kể cả câu bị loại. Nhãn do dự án đối chiếu nguồn tĩnh. Cần người đánh giá độc lập và mẫu giữ riêng để kết luận về khả năng khái quát. [Hồ sơ tham chiếu và phạm vi](../eval/reference_units/python2024.atomic-v3.json)

## Ba ca có thể mở khi vấn đáp

- **C7 ở hai lượt đầu.** Câu có phần mô tả đúng thao tác nhưng sai kiểu giá trị trả về. Dòng 74 gán lại kết quả chuyển thành văn bản và dòng 75 trả biến đó. Bộ tự duyệt loại câu ở lượt đầu và giữ câu cùng chứng cứ ở lượt hai. Khi loại cả câu, báo cáo đầu mất một mục đúng.
- **C12 ở lượt ba.** Câu nói dữ liệu chưa được chuyển thành văn bản. Dòng được dẫn cho thấy đã chuyển. Bộ tự duyệt vẫn giữ câu.
- **C16 ở lượt ba.** Đối số ở dòng 257 và thân hàm ghi ở dòng 270–273 cùng chứng minh thao tác ghi tệp được nêu. Bộ tự duyệt loại câu đúng này. Mục nằm ngoài 36 đơn vị tham chiếu nên lỗi loại nhầm thể hiện trong bảng từng câu. [Bảng đối chiếu lượt ba](../deliverables/real-demo-evidence/web-python-quality/20261128T023637_4ad0f5f6/review.md)

Ở lượt ba, tất cả 36 câu giữ lại có trích dẫn. Đối chiếu nội dung cho 33 đúng, 1 sai và 2 thiếu căn cứ. Tỷ lệ thiếu căn cứ là 5,56%, vượt mục tiêu 5%. Hai câu thiếu căn cứ suy ra mục đích sử dụng từ dòng import.

## Bằng chứng đã đến được bước nào?

Với từng mục bị bỏ sót sau tự duyệt, bộ chấm dò các dòng trong đáp án qua kết quả VM rồi đối chiếu văn bản đã gửi trong ba loại yêu cầu tạo nhận định (`card_generate`, `operation_review`, `technique_review`). Trước khi so vị trí giữa các lượt, bộ chấm xác minh hash nguồn chuẩn hóa, nội dung và tọa độ của dòng chung. [Dữ liệu từng mục và hash nhật ký](../deliverables/real-demo-evidence/web-python-exposure.json)

| Tình trạng của mục bị bỏ sót | Lượt một | Lượt hai | Lượt ba |
|---|---:|---:|---:|
| Công cụ chưa trả đủ các dòng tham chiếu | 7 | 7 | 7 |
| Đã truy xuất đủ, một phần dòng vắng trong các yêu cầu tạo nhận định | 2 | 2 | 0 |
| Các dòng nằm rải ở nhiều yêu cầu | 2 | 2 | 3 |
| Đủ dòng trong một yêu cầu, báo cáo đầu vẫn chưa nêu đúng mục | 5 | 5 | 6 |
| Báo cáo đầu nêu đúng, mất mục sau tự duyệt | 1 | 0 | 1 |
| **Tổng bỏ sót trên 36 mục** | **17** | **16** | **17** |

Hai vấn đề cần xử lý riêng ở phiên bản kế tiếp. Đối với nhóm bảy mục đầu, cần đo xem truy vấn thích ứng có lấy được các dòng còn thiếu. Đối với nhóm đã có đủ dòng trong một yêu cầu, cần xem ngữ cảnh có đủ chứng minh thao tác và quan hệ hay chưa, rồi so báo cáo trước và sau thay đổi. Việc đếm dòng chỉ xác định thông tin đã đến đâu trong hệ thống.

## Tái lập

Trong bản clone của nhóm, chạy lệnh sau để đối chiếu hồ sơ công khai, kiểm đủ ba lần chạy, tính lại số đúng, sai, thiếu căn cứ, bỏ sót và F1. Lệnh chạy ngoại tuyến.

```powershell
.\.venv\Scripts\python.exe -m eval.web_report_quality
```

Trên máy lab giữ các nhật ký gốc, lệnh đầu dưới đây xác minh hash nhật ký và báo cáo, đối chiếu từng trích dẫn rồi dựng lại bảng chấm. Lệnh thứ hai kiểm lại phân loại các mục bỏ sót từ nội dung các yêu cầu đã gửi tới Qwen.

```powershell
.\.venv\Scripts\python.exe -m eval.web_report_quality --replay
.\.venv\Scripts\python.exe -m eval.web_report_exposure
```
