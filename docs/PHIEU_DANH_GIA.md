# Phiếu kiểm nhận định từ các run buổi 4

Phiếu này chưa chấm. Nhóm kiểm chứng độc lập từng câu, kể cả câu reviewer đã loại. Tách fixture khỏi malware public và bổ sung mục bỏ sót trước khi tính P/R/F1.

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
