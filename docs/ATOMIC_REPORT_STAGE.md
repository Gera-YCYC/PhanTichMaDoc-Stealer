# Thử nghiệm nhận định theo thao tác và chấm cùng đơn vị

## Kết luận hiện tại

Phần thử nghiệm mới mô tả đúng các lời gọi API đã kiểm tra, nhưng **chưa đủ độ bao phủ để thay báo cáo chính**. Chỉ chọn các thao tác dễ chứng minh sẽ làm Precision cao trong khi bỏ sót chuỗi hành vi. Các số đo dưới đây giữ cả hai mặt này; không đánh dấu ANALYSIS/TRUST hay toàn đồ án đạt.

Bản hiện tại có **265 kiểm thử phần mềm đạt trên Windows**, gồm kiểm hash, che dữ liệu riêng tư, phân chia raw/rejected, đơn vị trùng lặp và khóa dependency của bản tái lập. Đây là kiểm thử phần mềm, không phải265 mẫu độc hoặc điểm chất lượng phân tích.

Ba lượt dùng SLM cục bộ thật, nhận đặc trưng và đoạn nguồn có giới hạn đã được công cụ trong VM thu ở hai lượt ReAct trước. Đây là **thử nghiệm riêng phần báo cáo trên mẫu thật**, không phải demo chạy lại toàn bộ pipeline, không phải mẫu mô phỏng. Không khởi động VM hoặc thực thi mẫu trong đợt này. Demo chính vẫn dùng `Run-Demo.ps1` và VM như TEAM_SETUP.

| Thử nghiệm | SLM | Kết quả source audit | Bao phủ tập 29 đơn vị Python | Thời gian |
|---|---|---|---|---:|
| `20261127T223237_eb2876a8` Python | Qwen3 8B | 6/6 câu đủ căn cứ | 6/29; P=1; R=0,2069; F1=0,3429 | 39,5081 s |
| `20261127T223527_d5fb791e` Python | Qwen2.5 Coder 7B | 4/4 câu đủ căn cứ; loại nhầm 2 thao tác đúng | 4/29; P=1; R=0,1379; F1=0,2424 | 33,8093 s |
| `20261127T223332_6006a331` Gomorrah .NET | Qwen3 8B | 10/10 câu upload/giải mã ký tự response đủ căn cứ | Chưa có bộ đáp án nguyên tử .NET: R/F1=`null` | 42,6311 s |

P=1 ở đây chỉ áp dụng cho những câu hẹp được xuất trong từng thử nghiệm. Không có nhận định IOC/ATT&CK và chưa có kết luận độc/lành. Cả ba trả `inconclusive` và `full_analysis_completed=false`. Không so trực tiếp Recall/F1 này với số Precision theo câu của v8: đơn vị đánh giá khác nhau. Số đo thời gian là một lượt/model, không phải benchmark tốc độ có độ lệch thống kê.

[Receipt và phép so request](../deliverables/real-demo-evidence/atomic-report-stage/comparison.json), [Python8B](../deliverables/real-demo-evidence/atomic-report-stage/20261127T223237_eb2876a8/receipt.json), [.NET8B](../deliverables/real-demo-evidence/atomic-report-stage/20261127T223332_6006a331/receipt.json), [Python7B](../deliverables/real-demo-evidence/atomic-report-stage/20261127T223527_d5fb791e/receipt.json).

## Thay đổi kỹ thuật

`stealer_agent/operation_assertions.py` kiểm hash của fact, mẫu, nguồn và toàn bộ các dòng import/khởi tạo/lời gọi. SLM đọc từng khẳng định kèm đúng các dòng này rồi chọn hoặc từ chối. Phần mềm dựng câu theo vai trò đối số đã quy định; không cho model tự biến tên biến thành nội dung hoặc nhãn parser thành tên hàm. Ví dụ `smtp_send` là nhãn nội bộ, câu xuất ra nói tới `SMTP.sendmail`; `Passwords` trong `UploadFile` được ghi là biểu thức đường dẫn.

Catalog hiện có SQLite connect/SELECT, SMTP sendmail, shutil.make_archive, AES-GCM decrypt, WebClient.UploadFile và ASCII response decoding. Đầu ra dài quá hợp đồng, hash sai, thiếu dòng, nguồn không phải code hoặc đối số bị che được loại và ghi lý do. Mọi quyết định model giữ trong journal. Hash đúng chứng minh tính toàn vẹn dữ liệu, **không tự chứng minh parser hiểu đúng chương trình**; source audit riêng vẫn bắt buộc.

Phần này chỉ có trong runner thử nghiệm `scripts/replay_card_report.py --method operations`, chưa được gắn làm chế độ demo chính. Chưa dùng kết quả này để đổi model mặc định/Release. SLM chọn thao tác; template viết câu; cả hai phần được ghi rõ, không gọi là model tự viết toàn bộ báo cáo.

## Chấm cùng một đơn vị

`eval/atomic_units.py` nhận bốn đầu vào: tập đáp án, raw report, checked report và bản đối chiếu có nhãn từ source audit. Công cụ không sinh nhãn bằng model. Nó kiểm:

- SHA256 của ba đầu vào; mẫu và nguồn lập đáp án.
- Mỗi câu raw, kể cả bị reviewer loại, đều có bản đối chiếu.
- Khoảng ký tự của từng nhận định không chồng nhau và không bỏ phần chữ chưa chấm.
- Một đơn vị đúng phải trỏ tới đúng loại behavior/IOC/ATT&CK của đáp án. Khẳng định đúng ngoài phạm vi yêu cầu mở rộng đáp án trước, không âm thầm bỏ khỏi mẫu số.
- Câu lặp về cùng một thao tác chỉ được tính một lần; giữ riêng số câu lặp. Nhận định sai/thiếu căn cứ cũng không được nhân lên hoặc gộp tùy kết quả.
- Checked report phải phân chia nguyên vẹn tất cả ứng viên raw; không sửa câu hay giấu câu bị loại.

Với cùng đơn vị: P=Đúng/(Đúng+Sai+Thiếu căn cứ), R=Đúng/(Đúng+Bỏ sót), F1=2PR/(P+R). Tập đáp án chưa sẵn sàng cho chấm trả metric `null`. Tập dự đoán rỗng có Recall=0 nếu có đáp án, Precision/F1=`null`; không biến việc không trả lời thành điểm hoàn hảo. Có bảng riêng theo loại nhận định.

Tập [Python atomic-v1](../eval/reference_units/python2024.atomic-v1.json) có **26 hành vi, 1 IOC và 2 ATT&CK**, tách từ source audit 13 nhóm trước đó và đối chiếu lại đoạn nguồn. Đây là tập **development**, lập sau các lượt phát triển, không phải blind holdout, không có người thật/GV phê duyệt. Phạm vi là chuỗi dữ liệu mật khẩu/thẻ → lưu/nén → SMTP; chưa bao trùm lịch sử tải xuống/autofill hoặc toàn bộ binary. Vì vậy chỉ gọi đây là Recall/F1 trên phạm vi đã công bố.

T1555.003 và T1560.002 trong đáp án là suy luận phân tích tĩnh từ code và định nghĩa [Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/), [Archive via Library](https://attack.mitre.org/techniques/T1560/002/). Chúng không phải sự kiện runtime quan sát được. Ngữ nghĩa SELECT và sendmail đối chiếu [Python sqlite3](https://docs.python.org/3/library/sqlite3.html), [Python smtplib](https://docs.python.org/3/library/smtplib.html); chỉ thấy SELECT không đồng nghĩa đã giải mã dữ liệu.

Hai model Python nhận **messages và schema giống hệt theo SHA256**. Cả ba lượt dùng cùng manifest 23 file host `c182e61e6c6c614d52ba79b0279f9505916c51136b84e3a7fdc3c3a08719c9fb`. Context4096, seed42, num_predict1800; Qwen3 thêm think=false. Lượt8B Python dùng2153/284token; 7B2105/293; .NET8B4215/450. Free RAM nhỏ nhất lần lượt936.214.528/1.218.699.264/988.233.728byte. Không có tool call mới trong các lượt replay.

Các lời giải thích chọn/từ chối của model có câu bị giới hạn độ dài giữa chừng; chúng nằm trong log riêng và không được dùng làm truth. 7B từ chối nhầm connect và SELECT thẻ, được giữ như hai false-negative quyết định, không sửa log thành thành công.

## Tái lập

Trên máy đã có journal riêng của lượt ReAct, chỉ bật model:

```powershell
.\scripts\Start-LocalModel.ps1
.\.venv\Scripts\python.exe scripts/replay_card_report.py --run 20261127T211223_9602dfdd --config config/host.cards-qwen3-candidate.example.json --method operations --measured-revision
.\scripts\Stop-LocalModel.ps1
```

Thay config bằng `config/host.cards-candidate.example.json` để chạy7B. Thay run bằng `20261127T212209_478cc179` để thử .NET. Run mới luôn có ID mới. Thành viên không có journal này phải chạy mẫu thật trong VM để tạo journal của mình trước; không có fallback mock. Public receipt không chứa source/credential nên không thay được journal riêng.

`--measured-revision` dùng [reporter đã đo](../eval/reproductions/operation-assertions-v1/reporter.py), kiểm mọi dependency theo [manifest](../eval/reproductions/operation-assertions-v1/manifest.json) trước khi chạy. Thiếu hoặc đổi dependency thì dừng; bỏ cờ để thử bản hiện tại. Archive lịch sử được ráp lại sau các lượt đo, từng byte đã đối chiếu hash ghi lúc bắt đầu; không mô tả thành archive có trước lượt đo.

Ba journal cũ có trường `reporter_source_sha256` trỏ nhầm tới module cards. Hash reporter thực có trong `source_files` và receipt xuất bản; journal gốc được giữ nguyên. Runner hiện tại đã sửa để ghi module được chọn. Sau ba phép đo, bản hiện tại còn bổ sung chặn placeholder riêng tư và nguồn không phải code; không gán ba phép đo cũ cho các sửa này.

Tái tính số đo đã khóa:

```powershell
.\.venv\Scripts\python.exe scripts/record_atomic_stage_reference.py
.\.venv\Scripts\python.exe scripts/record_atomic_stage_results.py
.\.venv\Scripts\python.exe -m pytest -q
```

Script thứ hai chỉ nhận ba report có hash đã source-audit; không dùng nó để tự gán nhãn đúng cho run mới. Run mới cần bản đối chiếu riêng rồi dùng CLI `python -m eval.atomic_units --profile ... --raw ... --checked ... --mapping ... --output ...`.

## Việc tiếp theo

1. Mở rộng bằng chứng cho đọc/copy/fetch/write/MIME/SMTP TLS và thân helper; giữ phân biệt biến, literal, declaration, call.
2. Chứng minh liên kết dữ liệu thu thập → file/nén → đầu ra mạng. Thêm IOC và ATT&CK có căn cứ; khôi phục kết luận cấp mẫu. Không thay mục tiêu đồ án bằng catalog API hẹp.
3. Dùng tập đơn vị đã khai báo để đo việc bỏ sót, hoàn thiện đáp án .NET và đối chiếu cả baseline v8 trên cùng đơn vị trước khi tuyên bố cải thiện toàn hệ thống.
4. Chỉ sau đó tích hợp vào ReAct và chạy lại >=3 mẫu, ba lần ổn định và >=10 cặp injection trên cùng revision. Training và các gate toàn đồ án theo backlog hiện hành.

Sau đợt đo, đã dừng PID2600 đúng receipt; cổng11435 không lắng nghe, VMware0, GPU quan sát0/6144MiB. [Receipt](../deliverables/real-demo-evidence/runtime-stopped-after-atomic-stage.json). Không xóa weight hay đĩa VM.
