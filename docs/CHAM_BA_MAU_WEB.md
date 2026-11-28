# Bản web trên ba mẫu thật

Mở **Đánh giá** trong StealerLab và chọn mẫu ở đầu trang. Nhóm có thể kiểm tra một nhận định bằng số dòng, thấy bộ tự duyệt giữ hay loại nó, rồi mở **Mục còn thiếu** để đối chiếu với đáp án phát triển. Khi cần chạy trực tiếp, chọn mẫu trong thanh bên và bấm **Chạy điều tra**. Máy Windows chạy giao diện, agent và Ollama. Công cụ trong VM cô lập thực hiện phân tích tĩnh. [Hướng dẫn chạy và hỏi đáp](WEB_DIEU_TRA.md)

## Ba mẫu và điều kiện so sánh

Mỗi hàng là một tệp có SHA-256 riêng, được kiểm với hồ sơ mẫu trước khi chấm. Cả ba dùng cùng digest Qwen3 8B, cùng hash mã agent và cùng hash cấu hình sau khi bỏ trường chọn mẫu. Với Python, bảng dùng lượt đầu tiên trong chuỗi ba lần chạy dùng để đo ổn định. Hai lượt lặp còn lại chỉ tham gia phép đo độ ổn định và bảng riêng của Python. [Biên bản của ba lượt](../deliverables/real-demo-evidence/web-current-batch.json) · [Bảng ba lần lặp Python](CHAM_BAO_CAO_WEB.md)

| Mẫu phát triển | Ca của giảng viên | Nhận định đầu → giữ | Lượt công cụ / Qwen | Thời gian | Liên kết tĩnh có bằng chứng | Chi tiết |
|---|---|---:|---:|---:|---:|---|
| PythonStealer | Thay J, PyInstaller | 30 → 29 | 17 / 38 | 376,77 s | 3/7 | [Từng câu Python](../deliverables/real-demo-evidence/web-python-quality/20261128T021511_bec5b2e5/review.md) |
| Gomorrah | Thay I, .NET | 27 → 24 | 17 / 49 | 591,01 s | 1/7 | [Từng câu Gomorrah](../deliverables/real-demo-evidence/web-dotnet-quality/20261128T030521_c76fc69a/review.md) |
| Mercurial | Ca .NET bổ sung | 19 → 16 | 17 / 48 | 546,58 s | 0/7 | [Từng câu Mercurial](../deliverables/real-demo-evidence/web-dotnet-quality/20261128T031606_ca91de35/review.md) |

Slide hướng 6 nêu mẫu I là tệp .NET 5.632 byte, mẫu J là tệp PyInstaller khoảng 8 MB, SLM tối thiểu 7B. Giảng viên không cấp hai tệp đó. Nhóm dùng mẫu công khai theo định dạng và lưu kích thước, hash thật của từng mẫu. [Thông số và slide gốc](YEU_CAU_GIANG_VIEN.md) · [Manifest mẫu thực tế](../config/public-samples.json)

Ba lượt có nhật ký đầu–cuối. Hợp các lượt có năm công cụ phân tích khác nhau thành công. Mỗi tệp còn được quét YARA trong VM và khớp luật ở tập phát triển. Mức buổi 4 yêu cầu ít nhất hai công cụ. Buổi 6 yêu cầu ít nhất ba mẫu có nhật ký. Cả hai mốc đều có bằng chứng trên phiên bản web này. Sau khi kết thúc, VMware xác nhận VM đã tắt và cổng Ollama của dự án có 0 tiến trình lắng nghe. [Trạng thái máy sau khi chạy](../deliverables/real-demo-evidence/runtime-stopped-after-web-batch.json)

## Điểm trên cùng một phiên bản

| Báo cáo sau tự duyệt | Mục đúng / tham chiếu | Precision | Recall | F1 toàn bộ | F1 IOC và ATT&CK |
|---|---:|---:|---:|---:|---:|
| PythonStealer | 19/36 | 100% | 52,78% | 69,09% | 66,67% |
| Gomorrah | 11/40 | 84,62% | 27,50% | 41,51% | 0% |
| Mercurial | 5/21 | 71,43% | 23,81% | 35,71% | 50% |
| **Gộp theo đơn vị** | **35/97** | **89,74%** | **36,08%** | **51,47%** | **42,86%** |

Trước lọc có 36 mục đúng, 2 sai, 5 thiếu căn cứ và 61 bỏ sót. Sau lọc còn 35 đúng, 1 sai, 3 thiếu căn cứ và 62 bỏ sót. Mỗi mục trùng lặp trong một mẫu chỉ được đếm một lần. Phát hiện đúng ngoài hồ sơ 97 mục vẫn xuất hiện trong bảng từng câu. Từng hồ sơ đã được chốt trước các lượt trên. Nhãn dựa trên mã dịch ngược của mẫu phát triển và còn chờ người chấm độc lập.

| Tiêu chí từ slide | Kết quả trên phạm vi đã đo | Đối chiếu |
|---|---|---|
| Precision ≥ 80%, recall ≥ 70%, F1 ≥ 75% | 89,74%, 36,08%, 51,47% | Chỉ precision đạt khi gộp ba mẫu |
| F1 riêng IOC và ATT&CK ≥ 80% cho mức xuất sắc | 3/11 mục đúng, 8 bỏ sót, F1 42,86% | Thiếu cả chỉ báo và kỹ thuật |
| Verdict lành/độc đúng 100% | 0/3. Cả ba được gán `suspicious` trong khi nhãn mẫu là `malicious` | Chưa đạt |
| Có dẫn chứng ≥ 90%, thiếu căn cứ ≤ 5% | 69/69 câu có trích dẫn, 64/69 đúng về nghĩa, 4/69 thiếu căn cứ (5,80%), 1/69 sai | Đạt tỷ lệ trích dẫn, vượt ngưỡng thiếu căn cứ |
| Ổn định ba lần ≥ 80% | 71,05% trên một mẫu Python | Chưa đạt. Cần lặp trên .NET |
| YARA TPR ≥ 90%, FPR = 0 | Thí nghiệm tạo luật trước đó khớp 5/5 mẫu phát triển và báo nhầm 0/39 tệp sạch | TPR trên mẫu độc giữ riêng còn chờ đo |

Tỷ lệ thiếu căn cứ ở bảng này đếm theo **câu**, còn precision, recall và F1 đếm theo **đơn vị tham chiếu**. Một câu có thể chứa cả một chi tiết đúng và một chi tiết sai. [Cách chấm của giảng viên](YEU_CAU_GIANG_VIEN.md) · [Phép thử YARA](YARA_REAL_CORPUS.md)

## Mở đâu khi giảng viên hỏi

- **PythonStealer → Đối chiếu từng câu → C7.** Kiểm kiểu giá trị trả về ở dòng 74–75. Bộ tự duyệt loại cả câu ở lượt đầu, làm mất một ý đúng cùng với ý sai.
- **Gomorrah → C9.** Ở 4243, biến là phần tử hiện tại của bộ liệt kê. Câu của agent suy ra thư mục làm việc của tiến trình. Nhật ký cho thấy bộ tự duyệt vẫn giữ suy diễn này.
- **Mercurial → C17.** So dòng 419, 424 và 430. Agent nhầm một tham số của hàm bao với tham số thật của lời gọi mở provider. Với mẫu này bản đồ có 6 quan hệ cần kiểm thêm và 1 quan hệ chưa tìm thấy. Kết quả quét YARA khớp mẫu và kết quả phân tích luồng dữ liệu là hai phép đo riêng. [Biên bản Mercurial](../deliverables/real-demo-evidence/web-20261128T031606_ca91de35.json)

## Nhóm cần cải thiện ở đâu

Khi rà lại câu C12 của Mercurial, nhãn được sửa thành **Đúng**. Dòng 1518 thực hiện chuyển đổi rồi gán giá trị vào trường. Câu của agent mô tả phép chuyển đổi và không nêu kiểu khai báo của trường đích. Nhận định đúng này nằm ngoài hồ sơ 21 mục của Mercurial nên số mục bỏ sót giữ nguyên. Lịch sử Git ghi cả hai lần chấm. [C12 và lý do chấm](../deliverables/real-demo-evidence/web-dotnet-quality/20261128T031606_ca91de35/review.md)

Trong 62 mục còn thiếu, **27 mục** thiếu dòng ngay từ kết quả công cụ. **18 mục** đã có đủ dòng trong kết quả công cụ nhưng còn thiếu dòng trong các yêu cầu tạo nhận định. **3 mục** có dòng nằm ở nhiều yêu cầu, **13 mục** có đủ dòng trong một yêu cầu nhưng báo cáo đầu chưa nêu đúng, **1 mục** mất sau tự duyệt. Để kiểm lại, bộ chấm đối chiếu nội dung đã gửi ở các bước tạo nhận định với hash và vị trí nguồn. Việc có mặt của dòng tham chiếu chưa chứng minh ngữ cảnh đã đủ. [Python](../deliverables/real-demo-evidence/web-python-exposure.json) · [Gomorrah](../deliverables/real-demo-evidence/web-gomorrah-exposure.json) · [Mercurial](../deliverables/real-demo-evidence/web-mercurial-exposure.json)

Nhóm đã thử đổi đoạn, mở rộng đoạn và gửi thêm hai đoạn trên cùng nhật ký. Phương án cuối giúp bốn mục có đủ dòng trong cùng một đoạn nhưng tạo thêm 0 mục đúng sau tự duyệt. Phép thử duyệt lại trên Mercurial cũng tái hiện một câu sai được giữ và một câu đúng bị loại. [Kết quả chọn đoạn và duyệt](THU_CHON_DOAN_CHUNG_CU.md) · [Các việc còn lại](CONG_VIEC_CON_LAI.md)

## Kiểm lại từ Git

### Tìm thêm chứng cứ trong VM trên hai mẫu .NET

Mở **Đánh giá**, chọn Gomorrah hoặc Mercurial rồi mở **Tìm lại dòng nguồn còn thiếu**. Phép thử `search_aa2525df5080` bắt đầu tại cuối hai lượt gốc. VM dịch ngược lại từng mẫu bằng ILSpy và so SHA-256 toàn bộ đầu ra với hồ sơ đã chấm. Mỗi nhánh nhận cùng những dòng và truy vấn từng thấy trước đó. Nhánh cố định lấy bốn từ khóa đầu tiên chưa dùng trong danh sách có sẵn. Ở nhánh thích nghi, sau mỗi kết quả, Qwen chọn một tên từ các đối số hoặc lời gọi đã quan sát. Chương trình chấm vị trí nguồn sau khi kết thúc cả hai nhánh. [Biên bản, số dòng cần tìm và chi phí từng truy vấn](../deliverables/real-demo-evidence/web-dotnet-followup.json)

| Mẫu | Cách tìm | Mục lấy đủ các dòng còn thiếu | Số dòng mới khác nhau | Lượt tìm VM / gọi Qwen | Thời gian tìm |
|---|---|---:|---:|---:|---:|
| Gomorrah | Danh sách cố định | 5/14 | 65 | 4 / 0 | 3,686 s |
| Gomorrah | Qwen chọn theo chứng cứ | 1/14 | 105 | 4 / 4 | 34,227 s |
| Mercurial | Danh sách cố định | 1/6 | 113 | 4 / 0 | 0,524 s |
| Mercurial | Qwen chọn theo chứng cứ | 2/6 | 134 | 4 / 4 | 6,704 s |

Trên Gomorrah, các truy vấn cố định tìm đủ dòng cho năm mục liên quan đến trình duyệt. Nhánh thích nghi tìm đủ dòng cho mục `logs-fragment`, nằm ngoài năm mục đó. Trên Mercurial, cả hai nhánh tìm được `ip-message`. Chỉ nhánh thích nghi tìm thêm `hardware-message`. Tính cả hai mẫu, số mục đủ dòng là **6/20** với danh sách cố định và **3/20** với Qwen. Nhánh Qwen dùng 3.327 token vào và 69 token ra. Thời gian trong bảng tính phần chọn và tìm, sau bước chuẩn bị chung. Trình tự hai nhánh đảo giữa hai mẫu. Cache và lần nạp model có thể ảnh hưởng thời gian.

Hai nhánh thu những vị trí bổ sung cho nhau. Cộng hai kết quả sẽ sử dụng gấp đôi ngân sách, nên bảng giữ từng nhánh riêng. Các số đo này chỉ đánh giá **sự hiện diện của dòng nguồn** trên hồ sơ phát triển. Để một mục được tính vào recall của báo cáo, agent còn phải trích đúng dòng và phát biểu đúng ý. Lượt thử dừng trước bước tạo báo cáo. Nhóm giữ cấu hình demo hiện hành.

Ở máy thành viên, `python -m eval.dotnet_followup` tính lại số mục đủ dòng từ các tọa độ công bố. Trên máy có nhật ký riêng, thêm `--replay` để đối chiếu từng lượt tìm với lựa chọn cho phép và nguồn gốc của mẫu. Muốn chạy thí nghiệm mới, bật lab như khi trình diễn, đồng bộ và kiểm VM, rồi chạy `python -m eval.dotnet_followup --live` từ PowerShell thứ hai khi web đang rảnh. Lệnh này cần hai nhật ký gốc nêu đầu trang. Kết quả mới nằm trong `private/dotnet-followups/<mã thử>/receipt.json`. Bấm **Tắt lab** sau khi nhận kết quả.

### Điểm báo cáo của ba mẫu

```powershell
.\.venv\Scripts\python.exe -m eval.web_report_quality
```

Lệnh tính lại hai tầng chấm điểm cho ba lượt Python và hai lượt .NET, sau đó tính điểm gộp theo ba mẫu khác nhau. Trên máy lab có nhật ký riêng, thêm `--replay` để dựng lại các bảng từ báo cáo gốc. Để kiểm tra riêng việc phân phối các dòng nguồn tới Qwen, chạy các lệnh sau.

```powershell
.\.venv\Scripts\python.exe -m eval.web_report_exposure --sample python
.\.venv\Scripts\python.exe -m eval.web_report_exposure --sample gomorrah
.\.venv\Scripts\python.exe -m eval.web_report_exposure --sample mercurial
```
