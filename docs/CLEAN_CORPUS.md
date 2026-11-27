# Bộ file sạch thật cho phép đo báo nhầm

## Mục đích và nhãn

Bộ âm tính gồm `where`, `whoami`, `ipconfig`, `findstr`, `sort`, `ping`, `MSBuild` và `csc` lấy từ bản Windows/.NET đang cài. Đây là file chương trình thật, không phải marker mô phỏng stealer. PowerShell kiểm Authenticode `Valid`, publisher Microsoft, phiên bản, kích thước và SHA256 trước khi sao chép. Không chạy các file để thu dữ liệu.

Nhãn âm tính có nghĩa phần mềm hệ thống/công cụ phát triển đã biết, kỳ vọng không phải stealer. Chữ ký không chứng minh mọi cách sử dụng một tiện ích đều vô hại. Sáu file native và hai công cụ .NET chưa đại diện toàn bộ phần mềm sạch; cần thêm ứng dụng Python/PyInstaller lành tính có nguồn gốc độc lập.

Chỉ metadata được đưa vào Git. Mỗi thành viên lấy binary từ bản Windows họ được phép sử dụng; hash có thể khác theo bản cập nhật. Không ghi đè lock cũ khi hash thay đổi, phải tạo phiên bản corpus mới.

## Chuẩn bị

Không có lượt phân tích đang chạy, khởi động lab rồi thực hiện:

```powershell
.\scripts\Start-Lab.ps1
.\scripts\prepare_clean_corpus.ps1
.\.venv\Scripts\python.exe scripts/import_clean_corpus.py
```

Script đầu lưu bản sao và metadata ở `private/clean-corpus/`. Import dùng SSH ghim khóa, kiểm tám hash ở VM rồi tạo manifest riêng `/opt/stealer-lab/private/evaluation/real-yara-v1.json`. Nó không sửa manifest fixture đang dùng bởi tool server, không thay mẫu cũ và không chạy mẫu. File mới chỉ được phân tích trong VM.

Manifest có hai phần: `training` chứa năm mẫu độc public đã dùng phát triển, `holdout` chứa tám file sạch vừa khóa trước khi tinh chỉnh luật mới. Vì holdout chưa có mẫu độc độc lập, **TPR holdout phải để null**. Có thể đo FPR trên tám file sạch, nhưng không lấy TPR development ghép thành kết quả tổng quát hóa trên holdout.

## Còn phải làm

Đợt nhập thực tế ngày 28/11/2026 đã kiểm đủ tám hash trong VM và khóa cùng năm mẫu độc development. [Receipt nhập](../deliverables/real-demo-evidence/real-clean-corpus-import.json) và [manifest có nhãn/phiên bản](../eval/corpora/real-yara-v1.json) công bố metadata; chưa có số đo YARA trên bộ này. Tool server vẫn dùng corpus fixture cũ cho đến khi tích hợp profile riêng.

- Đo luật thật bằng YARA compile/match trong VM trên manifest riêng, ghi hash luật, từng file khớp/không khớp và mẫu số. Receipt nhập file không phải kết quả phát hiện.
- Thêm mẫu độc giữ riêng và ứng dụng Python/PyInstaller sạch; giữ riêng tập development khỏi dữ liệu dùng chốt ngưỡng cuối.
- Tích hợp lựa chọn corpus thực vào luồng sinh/kiểm luật của agent có cấu hình rõ. Manifest fixture lịch sử được giữ để không đổi nghĩa số đo cũ.
- Khi thử luật dựa trên kết quả holdout, coi dữ liệu đã nhìn thấy là development cho đợt sau hoặc công bố đúng hạn chế. Không đổi nhãn để đạt FPR=0.
