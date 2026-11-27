# Đơn vị hành vi tham chiếu và phép đo độ bao phủ

Profile `python2024.behavior-v1.json` định nghĩa 13 đơn vị chức năng từ source Python đã phục hồi: lấy khóa, copy/query/decrypt dữ liệu browser, ghi kết quả, tạo ZIP, tạo MIME attachment và gửi SMTP. Đây là phạm vi phát triển được công bố, chưa phải toàn bộ khả năng của file hay bộ test giữ riêng.

Các đơn vị do đối chiếu source định nghĩa; thiết kế đã biết lỗi của các run phát triển trước. Không dùng quyết định của bộ tự duyệt Qwen làm nhãn thật, không giả người thật/GV ký duyệt, không coi đây là một thử nghiệm mù. Không đưa file reference vào prompt của agent. Source/secret vẫn ở VM/private; Git chứa mô tả, tọa độ evidence và hash.

## Quy tắc ghép

Một câu đúng có thể diễn đạt tương đương một đơn vị theo tác dụng, không cần lặp tên API. Nhưng câu phải khẳng định đủ phần chức năng cần đo và citation của chính câu phải chứng minh tác dụng đó. Chỉ có query không mặc nhiên được tính đã fetch; chỉ có login không được tính có STARTTLS; chỉ nêu tên helper không đủ chứng minh decryption. Nhiều câu lặp cùng thao tác chỉ phủ một đơn vị. Câu đúng bị reviewer loại vẫn nằm trong độ bao phủ thô, đồng thời mất khỏi độ bao phủ sau lọc.

Đây là đơn vị **chức năng**, không phải từng instruction/AST node. Một số đơn vị gồm nhiều thao tác cấu thành; cần tiếp tục chuẩn hóa prediction thành cùng đơn vị trước khi dùng Recall/F1 cuối môn. `scoring_ready=false` nghĩa là chưa sẵn sàng chấm toàn đồ án, không cấm đo độ bao phủ của subset đã khai báo.

`eval/reference_coverage.py` chỉ tính từ bảng ghép được viết rõ; nó kiểm hash profile/audit/report, đủ mọi đơn vị, không lặp ID, chỉ cho câu được source audit chấm đúng phủ đơn vị. Script không tự suy nghĩa và không tự tạo nhãn. Raw sentence Precision và reference-unit coverage khác mẫu số nên không ghép chúng thành F1.

## Bằng chứng

[Kiểm source 13 đơn vị](../../deliverables/real-demo-evidence/python2024-reference-units-source-check.json) xác minh hash source, tọa độ và marker trong VM. Marker khớp không tự chứng minh mọi mô tả ngữ nghĩa đúng; phần mô tả là kết quả source audit cần review độc lập.

Run `20261127T193524_b2342ecf` phủ **7/13 đơn vị (53,85%)** trong câu thô và **6/13 (46,15%)** sau lọc. Bộ tự duyệt loại C2 dù citation có implementation giải mã, làm mất đơn vị lấy mật khẩu đã có bằng chứng. [Bảng ghép và lý do](../adjudications/python2024-dependency-context-v2-unit-mapping.json), [kết quả](../../deliverables/real-demo-evidence/python2024-dependency-context-v2-unit-coverage.json). Đây không phải Recall toàn corpus hoặc F1.

## Chạy lại phép tính cục bộ

```powershell
.\.venv\Scripts\python.exe -m eval.reference_coverage --profile eval/reference_units/python2024.behavior-v1.json --audit eval/adjudications/python2024-dependency-context-v2-full-audit.json --run runs/20261127T193524_b2342ecf --mapping eval/adjudications/python2024-dependency-context-v2-unit-mapping.json --output private/coverage-recomputed.json
```

Nhật ký raw nằm trên máy thực nghiệm, không được công bố vì có source/credential. Thành viên chạy mẫu thật sẽ có run ID và hash mới, phải lập bảng ghép riêng. Muốn kiểm lại tọa độ trên VM: chạy `scripts/verify_reference_units.py --profile ... --evidence-id ev_... --output private/unit-source-check.json` với record của cùng source đã phục hồi.

## ATT&CK và phạm vi còn thiếu

Các mapping là suy luận từ source audit theo [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) và [T1560.002 — Archive via Library](https://attack.mitre.org/techniques/T1560/002/). Dùng `shutil.make_archive` thuộc nhánh thư viện, không đổi thành Archive via Utility. Chỉ có SMTP chưa đủ khẳng định giao thức khác C2 theo [T1048](https://attack.mitre.org/techniques/T1048/); profile này chưa gán mã đó.

Còn thiếu chuẩn hóa đầy đủ đơn vị prediction, IOC, history/download/autofill, các module khác, tập .NET, bộ sạch và holdout. Giữ nguyên gate Recall/F1 và verdict cuối môn ở trạng thái chưa đạt.
