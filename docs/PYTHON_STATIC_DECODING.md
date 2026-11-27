# Giải mã tĩnh payload Python có provenance

Mẫu `public_python2024.bin` (SHA256 `7430d4ff91880ad8296ea94fe9c43aab5a92f1901386ffdc0c7a829359d210db`) là mẫu public 22.183.360 byte, không phải J khoảng 8 MB trong ví dụ slide. PyInstaller chứa entry Python 3.11; pycdc chưa khôi phục đầy đủ. pycdas cung cấp opcode và hằng số để phân tích tiếp.

## Kết quả backend đã kiểm thật

[Receipt smoke](../deliverables/real-demo-evidence/python-static-decoder-smoke.json) ghi công cụ `bounded-literal-decoder/1` chạy trong VM, mất 0,1559 giây, trả 338 dòng evidence gồm provenance và payload 332 dòng. Đây là direct backend smoke, không gán thành lượt SLM tự chọn công cụ. Nhật ký ReAct được ghi riêng.

Lượt ReAct mới `20261127T160346_4685a56a` đã tự gọi công cụ thật, hoàn tất 15 tool action/17 model call trong 215,2034 giây, 6 loại tool thành công. Hai claim được reviewer heuristic giữ, hai claim bị loại; verdict vẫn inconclusive. [Receipt riêng](../deliverables/real-demo-evidence/python-decoder-final-regression.json). RAM khả dụng thấp nhất quan sát giữa request là 286.461.952 byte, không phải peak toàn run. Chưa coi các claim được giữ là đã đúng ngữ nghĩa qua chấm độc lập.

Chuỗi biến đổi đã kiểm:

1. Hằng số Base64 tại evidence line 2027 trong output pycdas; nối lại các đoạn 600 ký tự theo `source_line` trước khi xử lý.
2. Giải Base64 thành wrapper Python 78.377 byte; SHA256 `135b7196caca0bbfdc9baa4a5c931bc50d4168aed56533768aa92bdb466f5b2c`.
3. Phân tích AST, chỉ xử lý các phép gán và transform cho phép: Base64 của hằng số, Fernet bằng khóa nằm ngay trong wrapper, zlib có giới hạn output, giải UTF-8.
4. Thu candidate Python 11.818 byte, 332 dòng; SHA256 `8d36f208e5cf351faef62e5a06fe1a1ce0a9a578ccd27f8bcf62f1fbc5594ca4`.

Payload có mã truy vấn `logins`, gọi hàm giải mật khẩu, tạo zip và gửi email qua SMTP. Đây là những điểm để đối chiếu bằng source; không tuyên bố đã đánh cắp thành công dữ liệu trên máy hay đã liên lạc máy chủ.

## Ranh giới bộ giải mã

Code ở [literal_decoder.py](../vm_tools/literal_decoder.py), worker riêng [decode_worker.py](../vm_tools/decode_worker.py). Công cụ nhận `evidence_id` đã thuộc đúng hash mẫu, không nhận đường dẫn hoặc shell do model đặt. Input phải là output Python thành công; dữ liệu snapshot và toàn bộ source giữ trong VM.

Không import module của mẫu, không gọi `eval`, `exec`, hàm, decorator hoặc nhánh điều khiển của mẫu. Import trong AST chỉ thành symbol nội bộ của whitelist. Biểu thức không hỗ trợ làm mất giá trị đã biết; không suy đoán nhánh hoặc dùng binding cũ sau phép gán không xác định. Tên `exec` trong wrapper có thể được ghi nhận, nhưng không được gọi.

Giới hạn: worker 35 giây, address space 1,5 GB, output tối đa 1,1 MB; dữ liệu giải mã tối đa 1 MB, AST 60.000 node, 12.000 lần xử lý biểu thức, depth 32, tối đa 8 candidate. zlib không được giải nén vô hạn. VM dùng cryptography 41.0.7 có trong Ubuntu image đã ghim hash; health chỉ bật công cụ nếu có thư viện. Môi trường khác phải kiểm health trước demo.

Nguồn kỹ thuật: [Python AST](https://docs.python.org/3/library/ast.html), [giới hạn output của zlib](https://docs.python.org/3/library/zlib.html#zlib.Decompress.decompress), [Fernet API](https://cryptography.io/en/latest/fernet/). AST parse vẫn cần giới hạn tài nguyên; việc không thực thi code không loại bỏ mọi rủi ro parser.

Đây là bộ giải mã literal có phạm vi hẹp, không phải interpreter hoặc deobfuscator tổng quát. Luna và các wrapper dùng cấu trúc khác có thể chưa giải được. Output gọi là **candidate source**; khác với pycdc decompile đầy đủ và khác với bằng chứng runtime. Chuỗi hash của từng transform và parent evidence giúp kiểm tra lại nguồn gốc.

## Kiểm thử

Các bài test xác minh nối đoạn, Base64/zlib, giới hạn nén, không gọi `eval/exec/open`, không chạy branch hoặc dùng module bị shadow. Fixture kiểm an toàn chỉ dùng cho kiểm thử phần mềm; receipt PythonStealer là dữ liệu thật. Fernet đã đi qua đường backend thật trong VM; bộ unit test host không giả định host có cryptography.
