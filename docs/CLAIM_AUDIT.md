# Đối chiếu nhận định với mã nguồn đã thu

Ngày cập nhật: 28/11/2026. Đây là kiểm chứng trên mẫu phát triển PythonStealer2024, không phải kết quả nghiệm thu toàn corpus. Các câu được so với **chính đoạn chúng dẫn**, sau đó đối chiếu profile source; không lấy kết quả tự duyệt của Qwen làm đáp án. Nhãn do source audit tự động lập, chưa có người thật hoặc giảng viên phê duyệt.

## Ba phép thử và phạm vi

| Lượt | Cách chạy | Câu thô | Đúng / sai / thiếu căn cứ | Precision câu thô | Kết luận sau kiểm |
|---|---|---:|---:|---:|---|
| `20261127T164056_2bc4e796` | ReAct + VM, báo cáo đoạn v1 | 12 | 8 / 0 / 4 | 66,67% | malicious; căn cứ kết luận còn lỗi |
| `20261127T170742_b4a898c6` | SLM thật, 3 đoạn lưu sẵn, v2 | 6 | 6 / 0 / 0 | 100% trên 6 câu này | malicious dù tập câu được giữ không có khâu gửi |
| `20261127T171819_406f8937` | ReAct + VM, báo cáo đoạn v3 | 10 | 7 / 1 / 2 | 70% | suspicious; chưa đạt yêu cầu verdict của mẫu độc |

Số đoạn và hành vi được mô tả khác nhau giữa các lượt; bảng này không phải A/B thuần prompt/model. Phép thử v2 không gọi công cụ mới và không được dùng làm demo end-to-end. Không dùng 100% trên sáu câu được giới hạn trước để tuyên bố sản phẩm chính xác 100%.

## Những lỗi cụ thể phải tiếp tục xử lý

- **Import thành hành vi:** v1 nhận import requests/smtplib là hoạt động HTTP/email. V2 trở đi chặn các khối chỉ có import/using; không suy benign khi bỏ qua chúng.
- **Tên hàm thành kết quả:** lời gọi `combine_and_zip_files()` hoặc biến `zip_path` không tự chứng minh đã tạo archive. Phải dẫn thêm thân hàm chứa thao tác nén. Tương tự, muốn nói đối số thứ tư là attachment cần dẫn chữ ký/thân hàm `send_email`, không chỉ dòng gọi.
- **Lẫn truy vấn với giải mã:** v3 C2 diễn đạt như SQLite trả mật khẩu đã giải mã. Source có hai bước: SELECT lấy password_value, sau đó gọi decrypt_password. Nhận định cần giữ đúng thứ tự và ranh giới thao tác.
- **Đoạn bị cắt trước thao tác quyết định:** đoạn MIME kết thúc ở add_header chưa chứa `msg.attach(part)` phía sau. Không nhận là đã gắn attachment chỉ vì phần chuẩn bị đúng.
- **Reviewer loại sai:** các đoạn có `sqlite3.connect`/SELECT và AppData/Local/Temp/open/write vẫn bị tự duyệt phủ nhận. Tỷ lệ giữ câu không phải chất lượng. Cần đo cả loại nhầm câu đúng và giữ nhầm câu sai.
- **Vai trò ID do model gán còn sai:** v3 yêu cầu các nhóm thu dữ liệu, gửi dữ liệu và liên kết giữa hai bước. Đủ ba nhóm chỉ là kiểm đầy đủ tham chiếu; model vẫn có thể gán một lời gọi hàm thiếu thân hàm vào nhóm liên kết. Không gọi gate này là kiểm chứng luồng dữ liệu đầy đủ.

## Cách chấm và tái lập

`eval/claim_audit.py` kiểm hash report thô, đủ tất cả ID, và nội dung của các câu được giữ/bị loại khớp nguyên bản. Điểm chính luôn dùng toàn bộ câu thô. Điểm sau lọc được xuất riêng để kiểm reviewer; không thay mẫu số chính bằng tập tốt hơn.

```powershell
.\.venv\Scripts\python.exe eval/claim_audit.py runs/20261127T171819_406f8937 eval/adjudications/python2024-qwen3-cards-v3-full-audit.json --output evidence/local/cards-v3-score.json
```

Lệnh cần journal/report riêng tư của đúng lần chạy. Thành viên clone repo sẽ có hồ sơ nhãn và receipt công khai, nhưng phải tự chạy để có report cục bộ; không có raw source/credential của mẫu trong Git.

- [Chấm v1](../deliverables/real-demo-evidence/python2024-cards-v1-claim-score.json), [nhãn đủ 12 câu](../eval/adjudications/python2024-qwen3-cards-v1-full-audit.json).
- [Chấm v2 trên đoạn đã thu](../deliverables/real-demo-evidence/python2024-cards-v2-replay-score.json), [nhãn đủ 6 câu](../eval/adjudications/python2024-qwen3-cards-v2-replay-audit.json).
- [Chấm v3](../deliverables/real-demo-evidence/python2024-cards-v3-claim-score.json), [nhãn đủ 10 câu](../eval/adjudications/python2024-qwen3-cards-v3-full-audit.json), [receipt chạy VM thật](../deliverables/real-demo-evidence/cards-v3-python-run.json).

Recall/F1 hiện để `null`: profile có năm fact tổng hợp, còn câu model có độ chi tiết khác nhau và chưa có đối chiếu đầy đủ theo đơn vị nhất quán. Việc có nhiều câu đúng về ghi file không bù được thiếu luồng lấy mật khẩu/nén/gửi. Cần chốt các fact nguyên tử và phép ghép câu với fact trước khi chấm Recall; không đổi tập chuẩn theo các câu model tạo ra.

## Công việc kế tiếp

1. Ghép chứng cứ qua caller/callee với nguồn, đích và các phép biến đổi rõ; giữ cả khoảng dòng của hàm gọi lẫn hàm được gọi.
2. Tách các thao tác SQL, giải mã, ghi file, nén và gửi thành fact riêng; chỉ ghép luồng khi có bằng chứng truyền cùng dữ liệu.
3. Kiểm lại nhánh .NET, IOC/ATT&CK và luật YARA trên cùng revision đã chốt. Các mục này chưa được thay bằng bảng behavior hiện tại.
4. Hoàn tất bảng đối chiếu trên tập công bố, rồi mới đo ba lần ổn định, injection và các ngưỡng cuối môn. Không xem một nhãn malicious khớp là đủ căn cứ kết luận.
