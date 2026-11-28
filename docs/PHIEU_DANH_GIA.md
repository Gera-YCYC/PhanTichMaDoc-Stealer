# Phiếu kiểm nhận định từ các lần chạy thật

Trên AgentTesla, ba bảng sau cho thấy nội dung thay đổi qua các lượt cùng cấu hình. Có cả bảng cho lượt đối chứng tắt bộ xếp hạng. Mỗi lần chấm dùng cùng 7 mục nguồn đã chốt. [Lượt 1](../deliverables/real-demo-evidence/20261128T001144_4a8326ca/review.md) · [Lượt 2](../deliverables/real-demo-evidence/20261128T002926_2b0e57f6/review.md) · [Lượt 3](../deliverables/real-demo-evidence/20261128T003743_f8acf7f0/review.md) · [Lượt đối chứng](../deliverables/real-demo-evidence/20261128T002140_6b8034a7/review.md).

Mercurial có thêm 18 câu đã đối chiếu, đưa tổng số câu thô được chấm trên ba mẫu cùng phiên bản lên 87. Mỗi dòng ghi câu của agent, kết quả kiểm nguồn, dòng chứng cứ và quyết định của bộ lọc. [Mercurial](../deliverables/real-demo-evidence/20261128T000247_b054cbfb/review.md) · [Số liệu cùng phiên bản](DEMO_COVERAGE.md).

Bảng đối chiếu của đợt v11 đã có đủ 39 câu Python và 30 câu Gomorrah, kèm phần thiếu căn cứ, câu bị loại và những mục agent bỏ sót. Nhóm mở bảng tương ứng khi giảng viên muốn xem agent nói gì và nguồn chứng minh tới đâu. [PythonStealer 2024](../deliverables/real-demo-evidence/20261127T233612_212f9fbb/review.md) · [Gomorrah](../deliverables/real-demo-evidence/20261127T234632_6e94cea6/review.md).

Các dòng lịch sử buổi 4 trong bảng dưới còn chờ chấm. Nhóm kiểm chứng độc lập từng câu, kể cả câu reviewer đã loại. Tách fixture khỏi malware public và bổ sung mục bỏ sót trước khi tính P/R/F1.

| Run / mẫu | Agent nói | Dẫn chứng agent chọn | Thực tế / nhãn / người chấm |
|---|---|---|---|
| 20261127T123109_24605780<br>LabFixture.dll | The file is a .NET PE. | ev_c801cb76c6f94f61:5 —   "format": "PE .NET", | Chưa chấm |
| 20261127T123155_3c461577<br>safe_bundle.bin | The file is a PyInstaller bundle. | ev_4cc5105fc75b42ef:7 —   "pyinstaller_cookie_present": true | Chưa chấm |
| 20261127T123155_3c461577<br>safe_bundle.bin | The sample contains a URL that could be used for exfiltration. | ev_c523f3d4df774ddb:1 — {"type": "url", "value": "https://fixture.invalid/documentation", "source_evidence_id": "ev_43bce5fd55794e31", "source_line": 4, "classification": "candidate_not_confirmed_exfiltration"} | Chưa chấm |
| 20261127T123329_6da561af<br>public_gomorrah.bin | The file is a .NET PE. | ev_3c2d132c67cb4e4f:707 — 			CRYPTPROTECT_PROMPT_ON_UNPROTECT = 1, | Chưa chấm |
| 20261127T123329_6da561af<br>public_gomorrah.bin | The sample contains multiple IP addresses and URLs that could indicate exfiltration. | ev_ee6a5d09db124999:1 — {"type": "ipv4", "value": "1.0.0.0", "source_evidence_id": "ev_3c2d132c67cb4e4f", "source_line": 46, "classification": "candidate_not_confirmed_exfiltration"}; ev_ee6a5d09db124999:2 — {"type": "ipv4", "value": "11.0.0.0", "source_evidence_id": "ev_3c2d132c67cb4e4f", "source_line": 53, "classification": "candidate_not_confirmed_exfiltration"}; ev_ee6a5d09db124999:3 — {"type": "url", "value": "https://t.me/th3darkly", "source_evidence_id": "ev_3c2d132c67cb4e4f", "source_line": 3502, "classification": "candidate_not_confirmed_exfiltration"} | Chưa chấm |
| 20261127T125042_4ecdf290<br>LabFixture.dll | The file is a .NET PE. | ev_2f6a77ed62b2423d:5 —   "format": "PE .NET", | Chưa chấm |
| 20261127T125042_4ecdf290<br>LabFixture.dll | The assembly does not contain any network requests or credential access. | ev_85bf50486eb5412c:11 — 		return new string[4] { "SAFE_LAB_FIXTURE", "https://fixture.invalid/documentation", "Login Data is a documentation example, not accessed here.", "No network request or credential access is implemented." }; | Chưa chấm |
| 20261127T125144_f8ae9159<br>public_python2024.bin | The file is a Python script. | ev_1f85df6f9bff4295:5 —   "format": "PE", | Chưa chấm |

JSON để điền có cấu trúc: `eval/review-worksheet.json`. Không chạy score.py trực tiếp với phiếu chưa có nhãn.
Nguồn ground truth phải độc lập với chính output của agent. Log công cụ kiểm định dạng được, nhưng muốn xác nhận hành vi phải đọc code/luồng dữ liệu hoặc nguồn phân tích tương ứng.
## Mercurial với profile techniques-8b

Run `20261128T004729_8df9f715` có 19 câu đã đối chiếu, gồm cả 7 câu bộ tự duyệt loại. Trong 12 câu giữ có 9 đúng và 3 thiếu căn cứ. Mười mục trong đáp án 21 mục còn thiếu sau lọc. Thông tin IOC mà VM trích được có bảng riêng trong biên bản để người chấm phân biệt với nhận định của SLM. [Agent nói gì, trích dẫn ở đâu, nhãn và lý do](../deliverables/real-demo-evidence/20261128T004729_8df9f715/review.md) · [Kết quả các công cụ trong VM](../deliverables/real-demo-evidence/mercurial-techniques-v12-run.json).
