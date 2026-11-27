# Hồ sơ đối chiếu độc lập với báo cáo agent

Đã bổ sung [PythonStealer2024](../eval/reference_profiles/python2024.static.json): năm mục đối chiếu từ payload 332 dòng do công cụ giải mã tĩnh thu được, không dựa vào claim Qwen. Hồ sơ có hash bytes gốc CRLF và hash văn bản chuẩn hóa LF; không nhầm hai loại hash. Script `scripts/verify_python_reference.py` kiểm các marker tại dòng đã ghi trong VM. Đây vẫn là source audit, không phải review của người thật. Ánh xạ tạo zip bằng thư viện dùng T1560.002 (Archive via Library), không dùng kỹ thuật chạy utility chỉ vì cùng tạo ZIP.

Bản đầu tiên là `eval/reference_profiles/gomorrah.static.json`, lập từ kết quả ILSpy thật trong VM và nguồn phân tích của người công bố mẫu. Nó không lấy câu trả lời của Qwen làm đáp án. Đây là rà soát bằng công cụ/nguồn, **chưa có người trong nhóm ký duyệt**, chưa phải ground truth đầy đủ hoặc điểm nghiệm thu.

Mẫu: Gomorrah, SHA256 `93d03c6d0c24ce480a06e77c84b33e0bbc0d606fd055ef7cedf772db05c7891d`. ILSpy trả 5.008 dòng; output hash `cb2c5fe9b73249187551e5970da5c0637de37e8dd490695e24072bdd995693b5`.

| Mục đối chiếu | Chứng cứ mã tĩnh | Giới hạn |
|---|---|---|
| Browser credentials | SQLiteHandler nhận đường dẫn Opera/Chrome Login Data, ReadTable(logins), lấy username_value/password_value và gọi Decrypt | Không có credential của người thật bị đọc trong dự án |
| Gửi file mật khẩu | UploadFile(urlbot + đường dẫn logs.php, Passwords) | Cần nối tiếp chứng cứ cách tạo nội dung file; tên biến không đủ |
| Screenshot | CopyFromScreen, Image.Save(..., ImageFormat.Png) | Năng lực trong code, không phải quan sát runtime |
| Gửi screenshot | UploadFile với path_screenshot và screen.php | Chưa khôi phục chính xác urlbot |
| Cấu hình | Đọc executable của chính nó, tách theo chuỗi \|FS\|, lấy phần tử 1 vào urlbot | Đây là hướng trích cấu hình tiếp theo, không tự đoán endpoint |
| Phản ví dụ IOC | t.me/th3darkly xuất hiện trong dòng ghi công tác giả | Không phải bằng chứng webhook/Telegram bot exfiltration |

Nguồn công bố mô tả Gomorrah và HTTP exfiltration/C2 từ lần phân tích sandbox của họ năm 2020; dự án này không thực thi mẫu. [README nguồn cố định commit](https://raw.githubusercontent.com/jstrosch/malware-samples/1b3add9538fc40c0e59bd7488d267b1ec796a43d/binaries/gomorrah/2020/April/README.md).

Mapping browser credential access dựa trên [MITRE T1555.003](https://attack.mitre.org/techniques/T1555/003/). [T1555.004](https://attack.mitre.org/techniques/T1555/004/) là Windows Credential Manager, không phải nhãn cho mọi lời gọi DPAPI. [T1041](https://attack.mitre.org/techniques/T1041/) cần chứng cứ kênh C2; không gán chỉ vì thấy API upload.

Profile giữ ID/dòng/marker/hash để kiểm lại trong VM. Nó ghi rõ `dataset_split=development`, vì Gomorrah đã được dùng sửa prompt và controller. Không đổi nó thành holdout sau khi đã xem kết quả. Các profile Python/AgentTesla, nhãn file sạch, chấm raw/rejected claims và các mục bỏ sót còn phải hoàn thiện.
