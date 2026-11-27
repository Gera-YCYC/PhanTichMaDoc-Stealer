# Dữ kiện API có kiểu từ mã đã phục hồi

## Mục đích

Bản v4 có nhận định nhầm file gửi đi với response của `WebClient.UploadFile`, nhầm chuyển byte sang text với giải mã mật mã, và suy nội dung file từ tên biến. Ghi chú API và tự duyệt bằng cùng SLM vẫn chưa khắc phục đủ. Bộ phân tích này ghi riêng những thao tác có cấu trúc cú pháp và binding nằm trong phạm vi hỗ trợ để người đọc kiểm trực tiếp.

Đây là công cụ phân tích tĩnh trong VM, không chạy/import mẫu. Chưa phải bộ theo dõi luồng dữ liệu đầy đủ, không suy rằng lời gọi đã thành công, dữ liệu là bí mật hay file là mã độc chỉ từ tên API. Dữ kiện tool không tự biến thành nhãn đúng cho các câu SLM.

## Cấu trúc

- `vm_tools/operation_dotnet.py`: tree-sitter C#; nhận dạng overload hai đối số vị trí của WebClient.UploadFile với constructor cục bộ xác định được, và phép chuyển response byte sang ASCII trong cùng block.
- `vm_tools/operation_python.py`: AST Python; import trực tiếp sqlite3/smtplib/shutil, constructor và biến cục bộ nhìn thấy được; nhận dạng mở DB, SELECT, gửi SMTP và tạo archive.
- `vm_tools/operation_facts.py`: chuyển vị trí source về dòng chứng cứ bất biến; đóng gói sample hash, output hash, evidence ID, khoảng dẫn chứng và fact ID.
- `context_worker.py`: chọn dữ kiện liên quan đến vị trí tìm kiếm cùng các dòng đủ cho phạm vi binding hỗ trợ. Tối đa bốn dữ kiện mỗi lần, ngân sách dòng bổ sung 4.000 ký tự.
- `security.py`: loại dữ kiện nếu một khoảng dẫn chứng bị thiếu hoặc bị guard che. `engine.py` tích lũy vào `typed_operations`; `reporting.py` trình bày riêng với nhận định model.

## Ý nghĩa và ranh giới

`file_upload` tách `address_expression` với `file_path_expression`; return là response bytes. `response_text_decode` tách chuyển mã ký tự khỏi giải mã mật mã. `sql_select` mô tả truy vấn/cursor, không tự chứng minh đã fetch dữ liệu hay đã giải mã trường. `smtp_send` chỉ ra đối số message, chưa chứng minh message chứa dữ liệu lấy từ DB. `archive_create` chỉ ra lời gọi tạo archive; chưa xác định mọi file thực tế bên trong.

Binding được kiểm theo một tập dạng cú pháp hẹp. Reassignment, shadowing, using alias, keyword/starred argument chưa hỗ trợ và một số monkeypatch làm parser bỏ dữ kiện thay vì đoán. Closure/ref mutation, binding động và thư viện bị thay thế còn là giới hạn. LateGet/reflection chưa hỗ trợ. Không có dữ kiện không có nghĩa file lành.

## Kiểm chứng

Các test dùng source vô hại để kiểm vai trò tham số và những trường hợp dễ nhận nhầm. Bộ test không chứng minh độ chính xác trên malware.

[Receipt trên source thật trong VM](../deliverables/real-demo-evidence/typed-operations-real-source-check.json) kiểm hash các dòng ILSpy Gomorrah và source Python2024 đã giải mã tĩnh. Bản đầu nhận 10 thao tác .NET (5 upload, 5 chuyển response) và 12 thao tác Python (5 mở DB, 5 SELECT, 1 SMTP, 1 archive). Đây là chạy backend trên chứng cứ lưu trước đó; lượt ReAct mới phải có receipt riêng. Những file chứa argument/source chỉ nằm trong VM/private, không đưa lên Git.

## Bản v2 và kiểm tích hợp thực

Run v5 `20261127T184945_91217ab1` sử dụng backend `/1`: sáu dữ kiện đi từ VM vào `typed_operations`. Sau run, `/2` sửa nhãn return của SELECT thành cursor, không phải giá trị đã fetch/giải mã. Theo [tài liệu sqlite3](https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor), cursor quản lý truy vấn và thao tác fetch; gọi execute không thay cho fetchall. Bản v2 thêm citation cho import C#, loại `using` thuộc namespace khác và một số ref mutation, reimport, thay method rõ ràng. Mỗi fact mới có trường backend để tránh trộn revision.

[Backend v2](../deliverables/real-demo-evidence/typed-operations-v2-real-source-check.json) vẫn thu được 10 thao tác .NET và 12 Python từ record source thật. [Kiểm đường HTTP/worker/guard](../deliverables/real-demo-evidence/typed-operations-v2-delivery-check.json) chạy lại ILSpy, unpack, disassembly và decoder trên mẫu thật, rồi thực hiện sáu tìm kiếm. Source host/VM khớp, hash fact và mọi dòng citation tồn tại. Không gọi model trong phép thử này.

Hai lỗi thiết kế phép kiểm đã được sửa trước khi ghi receipt đạt: Evidence ID cũ không tồn tại trong session service mới, nên phép kiểm phải chạy lại tool lấy ID mới; truy vấn UploadFile rộng trả LateGet ngoài phạm vi hỗ trợ, nên fact rỗng được ghi rõ thay vì yêu cầu mọi truy vấn đều phải có fact. Dạng trực tiếp được kiểm bằng truy vấn riêng, không che trường hợp rộng chưa nhận dạng. Không coi phép kiểm có chủ đích này là bằng chứng SLM sẽ tự tìm đủ thao tác.

## Việc chưa hoàn thành

Chưa dùng các dữ kiện này để chứng minh luồng DB → biến → archive/message → kênh gửi. Chưa có đối chiếu đủ các đơn vị reference, chưa đo Recall/F1 cho tập thao tác, chưa chứng minh rằng thêm parser làm SLM chính xác hơn. Cần tích hợp có kiểm chứng vào báo cáo và đo trên cả mẫu phát triển, mẫu giữ riêng và bộ file sạch; vẫn giữ câu SLM sai trong mẫu số đánh giá.
