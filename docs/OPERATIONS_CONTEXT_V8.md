# Dữ kiện thao tác trong báo cáo và truy hồi hàm còn thiếu

## Vấn đề cần sửa

Ở run Python bản trước, model nhìn thấy helper AES nhưng reviewer vẫn loại câu giải mã đúng. Bộ chọn đoạn còn ưu tiên helper hostname ngắn đến trước, làm mất đoạn SMTP/đính kèm đầy đủ đến sau. Có các câu suy nội dung archive từ lời gọi hàm lưu file trong khi thân hàm lưu chưa được đọc. Danh sách 19 từ khóa đóng trong schema cũng ngăn agent tìm tên hàm mới gặp.

Đây là cải tiến trên tập **development** đã dùng để sửa phần mềm, chưa phải kiểm tra độc lập. Không lấy số unit test, fact hash hoặc tỷ lệ câu được cùng SLM giữ lại làm accuracy.

## Thay đổi

- `static-operation-facts/3` bổ sung dạng hẹp `AES.new(key, AES.MODE_GCM, nonce)` rồi gọi `decrypt(payload)` với import/binding cục bộ kiểm được. Kết quả là byte plaintext; không suy đã xác thực tag, đã decode text, có credential thật hay đã chạy thành công. Dạng keyword nonce, mode khác, binding động còn ngoài phạm vi hỗ trợ.
- Worker trong VM ưu tiên thao tác ngay tại hit tìm kiếm, sau đó thao tác trong callee đã trả về; vẫn tối đa 4 fact và 4.000 ký tự dòng bổ sung. Cách cũ chỉ theo khoảng cách có thể bỏ fact AES vì các câu SQL gần anchor hơn.
- `operation_context.py` kiểm backend, sample/evidence/output hash, fact hash và mọi dòng binding. Chỉ ghép fact vào đoạn chứa vị trí call; import chung không làm mọi fact trở thành liên quan. Nếu thiếu dòng hoặc dòng bị che thì bỏ fact. Mỗi card tối đa 3 fact, 6 khoảng và 4.600 ký tự source.
- `evidence-cards/8` chọn đoạn theo số thao tác chưa phủ và các dòng source nhìn thấy; xét toàn bộ ứng viên trước khi chọn. Đoạn đầy đủ đến muộn có thể thay đoạn ngắn nằm hoàn toàn trong nó. Generator và reviewer nhận cùng source cùng metadata thao tác. Metadata giúp đọc mã, không tự phê duyệt câu SLM.
- Controller mở rộng danh sách truy vấn bằng tên call/helper nhìn thấy trong các dòng đã chiếu, thay vì đóng cứng ở 19 từ khóa. `search_queries.py` chỉ lấy gợi ý từ vựng có giới hạn, bỏ dòng comment/quoted text/redaction; không resolve call hoặc mở file mẫu. Model chọn một literal trong tối đa 40 lựa chọn, gồm tối đa 24 tên từ source. Tên là dữ liệu không tin cậy, không phải bằng chứng hành vi. VM thực hiện tìm substring, không chạy regex/shell/mã của mẫu. Query lặp không phân biệt hoa/thường, đổi sample, evidence không hợp lệ và control character đều bị chặn.
- Sau bước disassembly, ưu tiên thử decoder được hỗ trợ rồi thực hiện phần tìm kiếm tối thiểu trước các thao tác tùy chọn. Model vẫn chọn truy vấn. Thay đổi này tránh để nghĩa vụ tìm kiếm dồn vào cuối ngân sách, khiến một câu trả lời lỗi làm không còn lượt kết thúc.
- `record_model_request` lưu nguyên messages, schema, evidence đã chiếu cùng hash trong nhật ký riêng. Request quá 512.000 byte bị từ chối thay vì cắt log rồi báo đủ provenance. Mọi controller/card/reviewer/replay dùng cùng cơ chế. Request lỗi hoặc run thiếu RAM vẫn được giữ đúng trạng thái.

## Bằng chứng đã có

[Kiểm source thật trong VM](../deliverables/real-demo-evidence/typed-operations-v3-real-source-check.json) nhận 10 thao tác .NET và 13 Python; Python có thêm một AES. [Kiểm qua HTTP](../deliverables/real-demo-evidence/typed-operations-v3-delivery-check.json) chạy lại công cụ với evidence ID mới, kiểm 7 tìm kiếm. [Kiểm card](../deliverables/real-demo-evidence/operation-context-v8-card-check.json) xác nhận các thao tác mục tiêu còn trong đoạn được chọn và có đủ dòng binding. Ba phép kiểm này không gọi SLM để chấm câu.

Lượt ReAct `20261127T203557_3580d286` dùng Qwen3 8B, gọi thành công 4 công cụ nhưng bị ngắt trước báo cáo: RAM host còn 199.147.520 byte. [Receipt lượt dở](../deliverables/real-demo-evidence/operations-v8-python-memory-stop.json) giữ 14 model call, 14 tool call và một lỗi pycdc. Không có điểm precision/recall/F1/verdict đạt cho lượt này. Ngưỡng RAM được giữ nguyên; chương trình đã yêu cầu unload model.

[Audit đầu vào của lượt dở](../deliverables/real-demo-evidence/model-projection-v8-incomplete-audit.json) kiểm đủ 14 messages và 14 schema, tái tạo 14 observation đã chiếu. Ba literal riêng tư được detector nhận diện không xuất hiện trong các request/schema/response. Gate chỉ áp dụng với literal đã nhận diện, không chứng minh detector tìm hết mọi bí mật. Các trường về báo cáo để `null` vì báo cáo chưa tồn tại.

Thử nghiệm trung gian `20261127T204500_5a3210fc` mở query dạng string tự do đã thất bại: 7 công cụ thành công nhưng có một truy vấn lặp và hai phản hồi không parse được, mỗi phản hồi chạm giới hạn 1.800 token; không có báo cáo. [Receipt](../deliverables/real-demo-evidence/operations-v8-open-search-incomplete.json) và [audit 18 request](../deliverables/real-demo-evidence/model-projection-v8-open-search-audit.json) được giữ. Bản hiện tại quay về enum có mở rộng theo source; không khẳng định nguyên nhân parser/grammar chỉ từ lần thử này.

Sau thay đổi tìm kiếm hiện tại, **221 kiểm thử phần mềm đạt trên Windows** trước lượt đo mới. Các test giả lập giao thức chỉ là unit test; demo dùng model và công cụ thật trong VM có receipt riêng. Source thực nghiệm được đóng gói theo manifest dưới `private/source-snapshots/`; thư mục này không đưa vào Git.

Lượt 7B với enum từ source chạy được nhưng trả rỗng cả 9 card. Bộ điều phối được sửa để báo cáo không có câu thô mang status `incomplete` và `has_model_findings=false`; log lịch sử giữ nguyên. Sau kiểm hồi quy, **222 test đạt**. Lượt Python Qwen3 8B trên bản sửa tạo 11 câu, audit đủ câu chấm 8 đúng/3 thiếu căn cứ, 4/6 đúng sau tự duyệt. [Receipt](../deliverables/real-demo-evidence/operations-v8-source-query-8b-python-run.json), [score](../deliverables/real-demo-evidence/python2024-operations-v8-claim-score.json). Nhận định dùng nhãn `smtp_send` như tên hàm là lỗi của model; đó chỉ là loại thao tác nội bộ. Không lấy kết quả này làm cải thiện accuracy hoặc đóng gate cuối môn.

## Diễn giải API

Tài liệu [PyCryptodome về GCM](https://www.pycryptodome.org/src/cipher/modern) tách `decrypt` khỏi `verify`/`decrypt_and_verify`. [Source PyCryptodome v3.20.0](https://github.com/Legrandin/pycryptodome/blob/v3.20.0/lib/Crypto/Cipher/__init__.py) hỗ trợ đối số nonce vị trí cho GCM. Đây là cơ sở diễn giải lời gọi trong source; chưa xác minh phiên bản thư viện thực sự được đóng gói trong mẫu.

## Điều kiện để chốt chất lượng

Phải chấm mọi câu thô theo chính các đoạn đã đưa cho model, gồm cả câu reviewer loại. Cần tách dữ liệu file gửi khỏi response, SELECT khỏi giải mã, call-site khỏi thân helper và biến đường dẫn khỏi nội dung file. Chưa có nối dữ liệu đầy đủ thì không nâng verdict dựa vào tên hàm. Lượt chạy thiếu RAM là lượt chưa hoàn tất; không tăng bộ nhớ bằng cách bỏ guard hoặc tắt ứng dụng khác trên máy.

Các tiêu chí còn lại giữ nguyên trong [backlog](CONG_VIEC_CON_LAI.md): corpus độc lập lành/độc, nhãn cùng đơn vị để tính Recall/F1, IOC/ATT&CK/YARA, ít nhất 3 mẫu trên cùng revision, stability 3 lượt, ít nhất 10 ca injection đủ exposure, và hồ sơ train/tái lập. Qwen chưa fine-tune; ranker truy hồi đã train là thành phần riêng.
