# Bộ mẫu công khai thay thế I/J

Người dùng xác nhận ngày 27/11/2026: giảng viên không cấp I/J, nhóm tự tìm nguồn public. Mẫu I/J và kích thước trên slide là tham chiếu đề tài, không phải định danh cho các file dưới đây.

| Mẫu tại VM | Nguồn | Kích thước thật | Trạng thái lựa chọn |
|---|---|---:|---|
| public_gomorrah.bin | jstrosch, Gomorrah .NET, 04/2020 | 85.041 B | Ứng viên chính nhánh .NET; ILSpy thành công |
| public_agenttesla.bin | jstrosch, AgentTesla SMTP, 04/2020 | 608.768 B | Mẫu bổ sung, cần đối chiếu dịch ngược |
| public_luna.bin | MalwareBazaar, LunaGrabber, 01/2026 | 23.250.383 B | PyInstaller 3.11, unpack được, pycdc cảnh báo; giữ làm ca khó |
| public_mercurial.bin | MalwareBazaar, Mercurial, 10/2021 | 43.008 B | Nhãn họ không chứng minh Python; nguồn ghi MSIL, không chọn thay J |
| public_python2024.bin | MalwareBazaar, PythonStealer, 03/2024 | 22.183.360 B | PyInstaller 3.11, unpack được, pycdc cảnh báo; chưa chốt làm mẫu chính |

Không file nào ở bảng được thực thi. Archive nguồn được chuyển vào VM để giải mã. Bộ Release lưu archive AES mã hóa ở host; plaintext chỉ ở VM. Không tải file mẫu lên dịch vụ phân tích cloud. Mọi truy vấn nguồn ngoài chỉ là đọc metadata hoặc tải dữ liệu đã công khai.

Đợt đo v11 dùng Gomorrah cho nhánh .NET, PythonStealer 2024 cho nhánh PyInstaller và AgentTesla để kiểm phạm vi trên mẫu thứ ba. MD5 `b0f2d519ccae5bf1435264e0979770ce` của AgentTesla trong VM khớp định danh của nhà nghiên cứu công bố quan sát SMTP. Bộ chấm phân biệt quan sát bên ngoài với điều agent tự chứng minh trong lượt chạy. [Biên bản đối chiếu](../deliverables/real-demo-evidence/agenttesla-atomic-source-check.json).

## Nguồn và định danh

**Gomorrah** — SHA256 `93d03c6d0c24ce480a06e77c84b33e0bbc0d606fd055ef7cedf772db05c7891d`.
[Nguồn và mô tả phân tích](https://github.com/jstrosch/malware-samples/tree/1b3add9538fc40c0e59bd7488d267b1ec796a43d/binaries/gomorrah/2020/April).
Kho có PCAP và mô tả exfiltration, cùng ví dụ decompiler. Đây là nguồn tham chiếu, không tự động biến mọi kết luận của agent thành đúng.

**AgentTesla** — SHA256 `a4fdc26d6b70eaf0a62cca36286412901f48881eae616d38b96d8ae0cb0f29c7`.
[Nguồn và mô tả SMTP](https://github.com/jstrosch/malware-samples/tree/1b3add9538fc40c0e59bd7488d267b1ec796a43d/binaries/agenttesla/2020/April).

**LunaGrabber** — SHA256 `d4f57b427a281c4dc32d6b8cc12195e0ce262c9f80ac8a8505ff3a0b47536324`.
[Hồ sơ MalwareBazaar](https://bazaar.abuse.ch/sample/d4f57b427a281c4dc32d6b8cc12195e0ce262c9f80ac8a8505ff3a0b47536324/),
[bài phân tích entry point cleaner.pyc](https://tekcookie75.github.io/2026-01-12-Python-Malware-on-the-rise/).
Mẫu có obfuscation; không coi giải nén thành công là phục hồi đầy đủ logic stealer.

**Mercurial** — SHA256 `926755cc31c239edc78b3ef4aa3b3cc64fbe7209d907f9d1cdaa4b560662adfc`.
[Hồ sơ nguồn](https://bazaar.abuse.ch/sample/926755cc31c239edc78b3ef4aa3b3cc64fbe7209d907f9d1cdaa4b560662adfc/).
Nguồn có nhãn MSIL. Dùng để minh họa phải xác minh định dạng thực tế, không chọn ngôn ngữ chỉ từ tên họ mã độc.

**PythonStealer 2024** — SHA256 `7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db`.
[Hồ sơ nguồn](https://bazaar.abuse.ch/sample/7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db/).
Entry point `thurs5`, Python 3.11, 156 mục archive. Cần bộ giải mã/giải rối phù hợp trước khi chốt chất lượng phân tích.

Cập nhật kiểm backend: pycdas đã đọc được **5.593 dòng bytecode** của entry `thurs5` trong VM (`evidence/local/pycdas-public-probe.json`). Đây là smoke test gọi backend trực tiếp, không tự tính là agent gọi tool. pycdc vẫn phát diagnostics, chưa phục hồi source hoàn chỉnh; hành vi payload còn cần phân tích độc lập.

Receipt tải/hash ở `evidence/local/public-*.json`. File `config/malwarebazaar.token` là bí mật tại máy, bị loại khỏi Git. [API chính thức](https://bazaar.abuse.ch/api/) yêu cầu Auth-Key; không ghi khóa vào lệnh hay báo cáo.

## Nguyên tắc xây đáp án

1. Chốt manifest hash, tập train và holdout trước khi tinh chỉnh luật.
2. Một thành viên đọc nguồn tham chiếu và chứng cứ VM, lập từng nhận định và citation độc lập với báo cáo agent.
3. Thành viên khác kiểm lại, đánh nhãn đúng/sai/bịa/bỏ sót. Nhận định không được kiểm chứng vẫn để pending.
4. Chỉ sau đó tính P/R/F1, hallucination, grounding, verdict, YARA TPR/FPR và stability.
5. Fixture lành tính và mẫu public thật có nhãn evidence riêng. Kết quả marker fixture không đại diện accuracy trên stealer.

## Điều kiện chốt bộ mẫu

Ít nhất một .NET stealer và một Python/PyInstaller stealer có kênh gửi/IOC phân tích được; ít nhất ba mẫu có log cho buổi 6; thêm file sạch và biến thể độc lập cho YARA. Hiện chưa có ground truth đầy đủ và chưa chốt mẫu Python chính. Giới hạn này phải giữ trong báo cáo tiến độ.
