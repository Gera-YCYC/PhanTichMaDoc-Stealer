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

## Bộ mở rộng và lần phát hiện báo nhầm

Bộ 8 file là phiên bản v1 được giữ nguyên. Bộ v2 có 37 tiện ích Microsoft có chữ ký hợp lệ và yt-dlp 2024.08.06 từ Release chính thức: tổng 38 file. Quét nguyên bộ luật v1 đã chỉ ra **1/38 báo nhầm** ở yt-dlp, hai luật Python cùng trúng. [Receipt kiểm lại độc lập](../deliverables/real-demo-evidence/yara-challenge-yara_real_14243d3cbc98.json).

Bộ v3 chuyển yt-dlp thành negative development, bổ sung gallery-dl 1.27.5: tổng **39 file sạch** khác hash, gồm hai ứng dụng PyInstaller hợp lệ. Mỗi manifest giữ nhãn, nguồn, kích thước và hash. Tên partition holdout không bảo đảm chưa từng xem; manifest ghi rõ tập nào đã dùng để sửa luật. [Luồng chuẩn bị và chạy](YARA_REAL_CORPUS.md).

## Lịch sử v1 và việc còn lại

Đợt nhập v1 ngày 28/11/2026 đã kiểm đủ tám hash trong VM và khóa cùng năm mẫu độc development. [Receipt nhập](../deliverables/real-demo-evidence/real-clean-corpus-import.json) và [manifest](../eval/corpora/real-yara-v1.json) giữ nguyên. Đã có profile `real-v1`/`real-v3` riêng; fixture vẫn giữ nguyên lịch sử.

- Đã chạy YARA thật với hash luật, từng kết quả và replay. Giữ số đo phiên bản riêng, không viết đè kết quả cũ.
- Đã bổ sung hai ứng dụng PyInstaller sạch. Để nói về khả năng tổng quát hóa, còn cần thêm họ/phần mềm độc lập và mẫu độc chưa dùng phát triển; đây không phải kết quả đã đo.
- Khi thử luật dựa trên kết quả holdout, coi dữ liệu đã nhìn thấy là development cho đợt sau hoặc công bố đúng hạn chế. Không đổi nhãn để đạt FPR=0.
