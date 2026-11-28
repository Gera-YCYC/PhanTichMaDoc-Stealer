# Chạy và kiểm tra bản Qwen3 8B

Mở PowerShell tại thư mục gốc trên máy Windows đã cài theo hướng dẫn nhóm. Máy thật chạy Ollama và điều phối ReAct. Máy ảo mở mẫu bằng trình đọc PE, trình dịch ngược hoặc công cụ đọc gói PyInstaller. Model nhận phần chứng cứ đã trích xuất và giảm dữ liệu nhạy cảm. Các mẫu được phân tích tĩnh bên trong VM. [Hướng dẫn chuẩn bị máy](TEAM_SETUP.md) · [Kiến trúc](KIEN_TRUC.md).

```powershell
.\scripts\Start-Lab.ps1 -PromptCacheMiB 0
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
.\scripts\Run-Demo.ps1 -Profile coverage-8b -Sample public_python2024.bin
.\scripts\Run-Demo.ps1 -Profile coverage-8b -Sample public_gomorrah.bin
.\scripts\Run-Demo.ps1 -Profile coverage-8b -Sample public_agenttesla.bin
.\scripts\Run-Demo.ps1 -Profile coverage-8b -Sample public_mercurial.bin
.\scripts\Stop-Lab.ps1
```

Đồng bộ mã trước lần chạy đầu của đợt đo. Nếu máy thành viên mới chỉ có model 7B, mở lab và chạy `python scripts/pull_model_candidate.py` một lần với mạng trên máy thật để bổ sung Qwen3 8B vào kho riêng của dự án. Đợt thực nghiệm yêu cầu cache prompt 0 MiB để giảm áp lực bộ nhớ. Giá trị này là tham số khởi động. Một lần chạy thành công chưa đủ để xác định tác động nhân quả của cache lên RAM.

Khi trình bày trực tiếp, chỉ vào dòng `CALL` để giải thích công cụ SLM chọn, tiếp đó chỉ vào tên backend và trạng thái trong dòng kết quả. Sau khi có `DONE`, mở `report.md` trong thư mục run ID vừa in. Đối chiếu một kết luận với ID chứng cứ và khoảng dòng trong báo cáo cục bộ. Giữ nhật ký riêng tại máy lab. Có thể mở hồ sơ kiểm chứng trong Git để thầy xem cách chấm. [Nguồn yêu cầu và đề xuất gốc](YEU_CAU_GIANG_VIEN.md).

## Agent tạo báo cáo như thế nào

Profile `coverage-8b` dùng Qwen3 8B để chọn công cụ theo phản hồi từ VM. Khi tổng hợp, agent nhóm các dòng mã đã đọc thành từng đoạn có số dòng gốc. Model đề xuất nhận định và tự kiểm mỗi nhận định. Một lượt bổ sung duyệt các thao tác API mà parser đã nhận ra, tối đa bốn thao tác mỗi yêu cầu. Mỗi câu được chọn mang các dòng chứng minh đối tượng gọi và đối số. Bộ kiểm trích dẫn đối chiếu ID mẫu, ID chứng cứ và nội dung rồi mới đưa danh sách câu đã giữ vào bước kết luận. Việc xếp vai trò thu thập, gửi và liên kết dữ liệu vẫn do model thực hiện. Đánh giá ngữ nghĩa bên dưới dùng kết quả đối chiếu nguồn riêng.

## PythonStealer 2024

Lượt `20261127T233612_212f9fbb` mất **588,6 giây**. Agent gọi pefile, pyinstxtractor, pycdas và bộ giải mã literal. pycdc báo lỗi. Agent tiếp tục đọc bytecode và mã ứng viên được khôi phục tĩnh. Có **17 lần gọi công cụ, 1 lỗi, 49 lần gọi SLM**, 96.401 token đầu vào và 3.330 token đầu ra. RAM khả dụng thấp nhất tại các điểm đo là 1.127.620.608 byte. Chi phí API ghi nhận là 0 USD. [Nhật ký rút gọn và nhận diện phiên bản](../deliverables/real-demo-evidence/python2024-coverage-v11-run.json).

| Chỉ số | Đã đo | Mục tiêu giảng viên |
|---|---:|---:|
| Precision trong đáp án đã chốt | 22/(22+3) = 88,00% | ≥ 80% |
| Recall | 22/36 = 61,11% | ≥ 70% |
| F1 theo cùng đơn vị | 72,13% | ≥ 75%, mức xuất sắc ≥ 80% |
| Nhận định nguyên câu có dẫn chứng đủ nghĩa | 36/39 = 92,31% | ≥ 90% |
| Nhận định nguyên câu thiếu căn cứ | 3/39 = 7,69% | ≤ 5% |
| Verdict | suspicious | Đúng lành/độc trên toàn bộ mẫu lab |

Đáp án development gồm 36 mục, được lưu trước khi có báo cáo cuối của lượt này. Tách 39 câu thành 46 nhận định theo nghĩa và gộp 12 nhận định trùng. Trong 34 nhận định phân biệt có 22 khớp đáp án, 9 có căn cứ ngoài phạm vi đã chốt và 3 thiếu căn cứ. Tính trên mọi nhận định phân biệt, Precision là 31/34 = 91,18%. Bảng trên dùng đúng 36 mục ban đầu để tính Recall và tính cả ba lỗi vào Precision. Bộ tự duyệt giữ cả 39 câu nên kết quả sau lọc trùng số thô. [Đáp án đóng băng](../eval/reference_units/python2024.atomic-v3.json) · [Nhãn và lý do từng câu](../eval/adjudications/20261127T233612_212f9fbb-judgments.json) · [Điểm theo nhận định](../deliverables/real-demo-evidence/20261127T233612_212f9fbb/atomic-score.json).

Agent xác định được cấu hình máy chủ SMTP và luồng gắn tệp nén vào email. Dữ liệu quan sát là mã tĩnh. Ba câu C10, C11 và C15 có phần suy ra tác dụng thu thập, ghi tệp hoặc giải mã từ chỗ gọi helper. Trích dẫn của từng câu thiếu thân hàm để chứng minh phần diễn giải đó. Báo cáo cũng bỏ sót hai ánh xạ ATT&CK trong đáp án cùng một số thao tác với dữ liệu thẻ. Ở bước verdict, model gán cả thao tác chuẩn bị thư hoặc AES vào vai trò gửi và tham chiếu các ID ngoài tập dùng để kết luận. Đây là các lỗi cần sửa trước khi dùng verdict để phân loại. [Bảng chấm nguyên câu](../deliverables/real-demo-evidence/20261127T233612_212f9fbb/claim-score.json).

## Gomorrah .NET

Lượt `20261127T234632_6e94cea6` gọi pefile và ILSpy trong VM. Sau 659,2 giây, agent kết luận `suspicious`. Bộ chấm nguồn ghi nhận 21/30 câu thô đúng, ba câu sai và sáu câu thiếu căn cứ. Sau tự duyệt còn 25 câu, trong đó 19 câu đúng. Model nhận biết các lời gọi tải tệp và phân biệt đúng một số thao tác giải mã ký tự ASCII trên dữ liệu phản hồi. Ở các câu khác, model suy tên tệp từ tên biến hoặc nhầm nội dung tệp gửi đi với dữ liệu máy chủ trả về.

Trên 40 đơn vị đã chốt, agent phủ 14 đơn vị, bỏ sót 26. Precision thô theo phạm vi là 60,87%, Recall 35,00%, F1 44,44%. Sau lọc lần lượt là 70,00%, 35,00% và 46,67%. Chín phát hiện thô khác có căn cứ ngoài phạm vi ban đầu. [Nhật ký rút gọn](../deliverables/real-demo-evidence/gomorrah-coverage-v11-run.json) · [Chấm nguyên câu](../deliverables/real-demo-evidence/20261127T234632_6e94cea6/claim-score.json) · [Chấm theo đơn vị](../deliverables/real-demo-evidence/20261127T234632_6e94cea6/atomic-score.json).

## Mercurial và AgentTesla

Ở Mercurial, ILSpy cho thấy một địa chỉ có cấu trúc webhook Discord tại dòng 37. Nhóm kiểm tra kiểu địa chỉ ngay trong VM và giữ kín phần định danh cùng khóa. Agent bỏ sót IOC này. Trong 18 câu thô, 10 câu đủ căn cứ. Sau lọc còn 11 câu, trong đó 9 đúng và 2 thiếu căn cứ. Một lỗi điển hình là suy ra tệp đã được truyền đi từ lời gọi hàm nhận đường dẫn tệp. Dòng gọi chứng minh việc chuyển đối số. Muốn xác nhận kênh gửi còn phải lần sang thân hàm và đối chiếu đích. Bộ 21 mục Mercurial được lập **sau khi xem kết quả**, dùng để phân tích lỗi trên mẫu phát triển. [18 nhận định và lý do](../deliverables/real-demo-evidence/20261128T000247_b054cbfb/review.md) · [Đối chiếu 30 dòng nguồn trong VM](../deliverables/real-demo-evidence/mercurial-atomic-source-check.json).

Ở AgentTesla, bản coverage đọc được PE và dịch ngược thành 3.345 dòng. Có 14 tìm kiếm rỗng và báo cáo cuối có 0 câu. Phiên mới `guided-8b` chuyển sang một trang mã chưa đọc khi hai lượt tìm liên tiếp không có kết quả. Nó ưu tiên trang có các lời gọi khác nhau, rồi để model chọn truy vấn tiếp theo. [Đáp án 7 mục](../eval/reference_units/agenttesla.atomic-v1.json) · [Lượt rỗng được giữ trong đợt đo](../deliverables/real-demo-evidence/agenttesla-coverage-v11-run.json).

## Đối chiếu đợt bốn mẫu

Cùng source, digest model và cấu hình điều phối, ba mẫu có báo cáo chứa nhận định và một mẫu kết thúc với báo cáo rỗng. Ba báo cáo có nhận định sử dụng tổng cộng năm công cụ phân tích khác nhau. Nhóm đã có bằng chứng cho mốc buổi 6. Nhóm có thể dùng video để giới thiệu kết quả trước khi chạy trực tiếp bằng lệnh PowerShell ở đầu trang. [Bằng chứng bốn lượt](../deliverables/real-demo-evidence/coverage-v11-batch.json) · [Video phát lại từ nhật ký](../deliverables/Demo_phan_tich_tinh.mp4) · [Hash video và nhật ký đầu vào](../deliverables/Demo_phan_tich_tinh.json).

| Mẫu | F1 mọi loại sau lọc | IOC + ATT&CK đúng / mục tham chiếu | F1 riêng IOC + ATT&CK | Câu có trích dẫn / câu đủ căn cứ sau lọc |
|---|---:|---:|---:|---|
| PythonStealer 2024 | 72,13% | 1/4 | 40,00% | 39/39 có trích dẫn, 36/39 đủ căn cứ |
| Gomorrah | 46,67% | 0/4 | 0% | 25/25 có trích dẫn, 19/25 đủ căn cứ |
| Mercurial | 72,22% | 0/3 | 0% | 11/11 có trích dẫn, 9/11 đủ căn cứ |
| AgentTesla, coverage | Chưa có nhận định | Đáp án 7 mục thuộc hành vi và quan sát | Chưa xác định | 0 câu |

Ba mẫu có bảng chấm cho kết quả gộp IOC + ATT&CK là **1 đúng, 10 bỏ sót, 0 sai, 0 bịa** sau lọc trong phạm vi đã khai báo. F1 gộp là 2/(2+10) = **16,67%**. Có thể kiểm tra các bộ đếm trong trường `rubric_ioc_attack` của từng bảng điểm. Các mẫu số trên phản ánh tập development của nhóm. Cả bốn lượt đều chưa đưa ra verdict `malicious` nên độ đúng verdict trên bốn mẫu độc trong đợt này là **0/4**. [Python](../deliverables/real-demo-evidence/20261127T233612_212f9fbb/atomic-score.json) · [Gomorrah](../deliverables/real-demo-evidence/20261127T234632_6e94cea6/atomic-score.json) · [Mercurial](../deliverables/real-demo-evidence/20261128T000247_b054cbfb/atomic-score.json).

## Đối chiếu các bản trước

Trên bản v10, phép kiểm thông tin thực sự có trong yêu cầu sinh báo cáo tìm được 14/34 mục bị bỏ sót dù mọi dòng tham chiếu của mỗi mục đã nằm trong cùng một yêu cầu. Bốn mục được nêu rồi bị loại ở bước tự duyệt, bốn mục còn thiếu dòng trong yêu cầu, một mục bị chia giữa nhiều yêu cầu và 11 mục được giữ. Số liệu đo sự có mặt của dòng trong đầu vào. [Kết quả theo từng mục](../deliverables/real-demo-evidence/python2024-cards-v10-missed-unit-exposure.json).

Nhánh .NET có đáp án development gồm **40 mục**. Trình kiểm đối chiếu 46 dòng riêng biệt trên bản ILSpy có SHA-256 cố định. Lượt Gomorrah v8 từng phủ 14/40 mục, F1 thô 46,67%. Thử nghiệm trước đó chỉ chọn các thao tác API phủ 10/40 mục. Hai kết quả lịch sử dùng chung đáp án .NET. [Đáp án Gomorrah](../eval/reference_units/gomorrah.atomic-v1.json) · [Biên bản kiểm nguồn](../deliverables/real-demo-evidence/gomorrah-atomic-source-check.json).

## Tái tính điểm

Lệnh dưới đây đọc nhật ký trên máy thực nghiệm, xác minh chuỗi hash, so khớp báo cáo cuối và từng trích dẫn rồi áp dụng bảng chấm đã khóa theo hash. Một lần chạy mới cần bảng chấm riêng. Người chấm có thể phản biện từng nhãn qua ID, dòng nguồn và lý do trong bảng. Hiện các nhãn là kết quả đối chiếu kỹ thuật của dự án, chưa có chấm độc lập của giảng viên.

```powershell
.\.venv\Scripts\python.exe scripts/score_reviewed_run.py --directory runs/20261127T233612_212f9fbb --profile eval/reference_units/python2024.atomic-v3.json --judgments eval/adjudications/20261127T233612_212f9fbb-judgments.json --output private/kiem-diem-python
```
