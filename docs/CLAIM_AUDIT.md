# Đối chiếu nhận định với mã nguồn đã thu

Ngày cập nhật: 28/11/2026. Đây là kiểm chứng trên các mẫu phát triển PythonStealer2024 và Gomorrah, không phải kết quả nghiệm thu toàn corpus. Các câu được so với **chính đoạn chúng dẫn**, sau đó đối chiếu profile source/API; không lấy kết quả tự duyệt của Qwen làm đáp án. Nhãn do source audit tự động lập, chưa có người thật hoặc giảng viên phê duyệt.

## Các phép thử và phạm vi

| Lượt | Cách chạy | Câu thô | Đúng / sai / thiếu căn cứ | Precision câu thô | Kết luận sau kiểm |
|---|---|---:|---:|---:|---|
| `20261127T164056_2bc4e796` | ReAct + VM, báo cáo đoạn v1 | 12 | 8 / 0 / 4 | 66,67% | malicious; căn cứ kết luận còn lỗi |
| `20261127T170742_b4a898c6` | SLM thật, 3 đoạn lưu sẵn, v2 | 6 | 5 / 0 / 1 | 83,33% theo bản chấm sửa lần 2 | malicious dù tập câu được giữ không có khâu gửi |
| `20261127T171819_406f8937` | ReAct + VM, báo cáo đoạn v3 | 10 | 7 / 1 / 2 | 70% | suspicious; chưa đạt yêu cầu verdict của mẫu độc |
| `20261127T175019_6cbdf3e9` | ReAct + VM, ghép caller/callee v4 | 16 | 8 / 3 / 5 | 50% | suspicious; bộ tự duyệt giữ 14 câu nhưng có 8 câu sai/thiếu căn cứ |

Số đoạn và hành vi được mô tả khác nhau giữa các lượt; bảng này không phải A/B thuần prompt/model. Phép thử v2 không gọi công cụ mới và không được dùng làm demo end-to-end. Bản chấm đầu từng ghi 6/6; khi áp dụng nhất quán điều kiện chứng cứ cho hàm tự định nghĩa, C4 phải chuyển sang thiếu căn cứ vì citation chỉ có lời gọi decrypt_password mà không có thân hàm. Bản chấm/score cũ được giữ, bản sửa lần 2 ghi hash và nhãn trước đó; report thô của model không bị sửa.

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
- [Chấm v2 sửa lần 2](../deliverables/real-demo-evidence/python2024-cards-v2-replay-score-revision2.json), [nhãn và lý do điều chỉnh](../eval/adjudications/python2024-qwen3-cards-v2-replay-audit-revision2.json). [Bản chấm đầu](../deliverables/real-demo-evidence/python2024-cards-v2-replay-score.json) chỉ để truy vết.
- [Chấm v3](../deliverables/real-demo-evidence/python2024-cards-v3-claim-score.json), [nhãn đủ 10 câu](../eval/adjudications/python2024-qwen3-cards-v3-full-audit.json), [receipt chạy VM thật](../deliverables/real-demo-evidence/cards-v3-python-run.json).
- [Chấm v4](../deliverables/real-demo-evidence/python2024-cards-v4-claim-score.json), [nhãn đủ 16 câu](../eval/adjudications/python2024-qwen3-cards-v4-full-audit.json), [receipt chạy VM thật](../deliverables/real-demo-evidence/cards-v4-python-run.json). Sau lọc chỉ 6/14 câu đúng (42,86%); hai câu đúng bị loại. Tỷ lệ thiếu căn cứ của tập thô 31,25%, grounding 50%; không đạt các ngưỡng tin cậy.

V4 đã đưa thêm thân hàm tạo archive, gắn MIME và gọi SMTP vào cùng mục chứng cứ. Tuy nhiên, model vẫn gộp truy vấn với giải mã khi thiếu thân hàm giải mã; hiểu sai bộ đếm thành nơi ghi dữ liệu; tự duyệt không phân biệt tốt câu đúng và câu thiếu căn cứ. Số câu nhiều hơn hoặc thêm quan hệ cú pháp không tự làm chất lượng tốt hơn. Giới hạn lấy bốn mục liên kết còn khiến hai helper song song chiếm chỗ của helper giải mã cần thiết. Cần kiểm từng thao tác và quan hệ truyền dữ liệu thay vì tiếp tục chỉ kéo dài đoạn source.

Recall/F1 hiện để `null`: profile có năm fact tổng hợp, còn câu model có độ chi tiết khác nhau và chưa có đối chiếu đầy đủ theo đơn vị nhất quán. Việc có nhiều câu đúng về ghi file không bù được thiếu luồng lấy mật khẩu/nén/gửi. Cần chốt các fact nguyên tử và phép ghép câu với fact trước khi chấm Recall; không đổi tập chuẩn theo các câu model tạo ra.

## Đối chiếu đầy đủ .NET v4

Run `20261127T180215_b3a8ccf4` đã chấm đủ **19 câu thô: 7 đúng, 4 sai, 8 thiếu căn cứ**. Precision 36,84%, hallucination 42,11%, grounding 36,84%. Sau bộ tự duyệt chỉ 2/9 câu được giữ là đúng (22,22%); 5 câu đúng bị loại. Recall/F1 vẫn để null vì chưa chốt đầy đủ đơn vị fact tham chiếu. [Nhãn và lý do từng câu](../eval/adjudications/gomorrah-qwen3-cards-v4-full-audit.json), [kết quả tính](../deliverables/real-demo-evidence/gomorrah-cards-v4-claim-score.json).

Tất cả khoảng quote trong hồ sơ này đã so khớp với observation lưu trong journal của đúng run. Phép chấm phân biệt quan sát hẹp như constructor nhận đường dẫn cụ thể với khẳng định về tác dụng của hàm tự định nghĩa: muốn xác nhận hàm giải mã phải có thân hàm chứa thao tác tương ứng. Một tên Decrypt hoặc khai báo DATA_BLOB chưa đủ; việc lấy 36 dòng đầu helper dài gặp nhiều boilerplate ILSpy khiến thao tác cần chứng minh vẫn nằm ngoài citation.

- C1/C2/C9/C10 có căn cứ upload nhưng bị tự duyệt loại: source xác định instance WebClient, tên member và mảng đối số truyền vào LateGet. Tài liệu [NewLateBinding.LateGet](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.compilerservices.newlatebinding.lateget?view=net-10.0) xác định Instance, MemberName và Arguments. Đây là phân tích khả năng tĩnh, không khẳng định đã gửi thành công lúc chạy.
- C11/C13 nhầm mảng byte trả về với dữ liệu file gửi đi. Theo [WebClient.UploadFile](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.uploadfile?view=net-10.0), hai tham số là địa chỉ và tên/đường dẫn file; giá trị trả về là thân phản hồi. Tên biến Passwords/CC/emails_pass chưa chứng minh nội dung của file đó.
- C11/C15 mô tả ASCII GetString như giải mã mật mã. [ASCIIEncoding.GetString](https://learn.microsoft.com/en-us/dotnet/api/system.text.asciiencoding.getstring?view=net-10.0) chuyển byte thành ký tự theo encoding; đoạn được dẫn không có thao tác giải mã mật mã.

Kết quả này xác nhận cần sửa cách biểu diễn thao tác/đầu vào/đầu ra và chọn phần hữu ích trong helper. Không thể dùng việc reviewer giữ một câu hoặc đủ ID cho các vai trò verdict làm bằng chứng ngữ nghĩa đúng.

## Python v5: đã chấm đủ câu, vẫn chưa đạt

Run `20261127T184945_91217ab1` có 16 câu thô: 10 đúng, 1 sai, 5 thiếu căn cứ. Precision/grounding 62,5%, hallucination 31,25%; Recall/F1 vẫn null. Reviewer giữ 15 câu, trong đó 9 câu đúng; bỏ nhầm C9 mô tả việc copy Login Data có trong chính citation. [Hồ sơ đầy đủ](../eval/adjudications/python2024-qwen3-cards-v5-full-audit.json), [score tái tính được](../deliverables/real-demo-evidence/python2024-cards-v5-claim-audit-score.json).

C8 chỉ dẫn phần cấu hình/header nhưng khẳng định gửi attachment; C10/C12 thiếu thân helper giải mã; C14 thiếu dòng mở đường dẫn attachment; C15 hiểu total_browsers thành nơi nhận dữ liệu; C16 chỉ dẫn lời gọi helper mà thiếu implementation. Chấm theo chính chứng cứ câu đã nộp, không lấy đoạn khác của file để hợp thức hóa citation thiếu. Nhãn là source audit, chưa có người thật ký duyệt.

Lượt này có sáu typed operations nhưng chúng chưa được dùng trong prompt/card nên không quy thay đổi Precision cho parser. Prompt, thứ tự review schema và ngữ cảnh đã đổi so với v4; chưa phải thí nghiệm kiểm soát để xác định tác động riêng từng thành phần. Bộ suy luận reviewer thử ba câu cũng chưa loại đúng câu thiếu căn cứ, xem [thực nghiệm API/reference](API_REFERENCE.md).

## Công việc kế tiếp sau khi chấm hai nền tảng

Nhánh .NET còn có [chín phản ví dụ source/API](../eval/adjudications/gomorrah-qwen3-cards-v3-counterexamples.json). Ba câu nhầm byte trả về của UploadFile thành dữ liệu file gửi đi; một câu suy phản hồi/SMTP qua sai API; các câu khác thiếu thân hàm hoặc thao tác cuối. Theo [tài liệu Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient.uploadfile?view=net-10.0), UploadFile nhận đường dẫn file và trả thân phản hồi từ resource. Chuyển mảng trả về đó sang ASCII là xử lý phản hồi, không phải chuyển file thành ASCII trước khi gửi. Đây là kiểm một phần, không tính Precision/F1 cho đủ 20 câu từ chín phản ví dụ này.

1. Ghép chứng cứ qua caller/callee với nguồn, đích và các phép biến đổi rõ; giữ cả khoảng dòng của hàm gọi lẫn hàm được gọi.
2. Tách các thao tác SQL, giải mã, ghi file, nén và gửi thành fact riêng; chỉ ghép luồng khi có bằng chứng truyền cùng dữ liệu.
3. Kiểm lại nhánh .NET, IOC/ATT&CK và luật YARA trên cùng revision đã chốt. Các mục này chưa được thay bằng bảng behavior hiện tại.
4. Hoàn tất bảng đối chiếu trên tập công bố, rồi mới đo ba lần ổn định, injection và các ngưỡng cuối môn. Không xem một nhãn malicious khớp là đủ căn cứ kết luận.
