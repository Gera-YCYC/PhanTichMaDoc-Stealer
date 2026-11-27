# Bản chứng cứ dành cho mô hình

`model-evidence-projection/1` tạo bản xem đã che literal nhạy cảm **trước khi** controller nén ngữ cảnh, chọn card và gọi SLM. Mục đích là giảm việc mô hình nhắc lại mật khẩu/email/token lấy từ mã mẫu. Đây là lớp riêng với guard chống prompt injection; tắt guard để đo injection vẫn giữ lớp che literal.

## Luồng dữ liệu

1. Công cụ trong VM tạo chứng cứ bất biến, có SHA256 mẫu, SHA256 output và số dòng gốc.
2. Host nhận một trang/excerpt giới hạn. Nhật ký riêng lưu `raw` để đối chiếu.
3. Guard xử lý chuỗi giống chỉ dẫn. `ModelEvidenceView` nhận diện assignment/login chứa literal, email và một số định dạng webhook/token; thay giá trị bằng nhãn `__PRIVATE_LITERAL_n__` nhất quán trong lượt chạy.
4. Nếu vừa nhận diện thêm giá trị, controller che nó trong các đoạn đã giữ trong bộ nhớ. Việc này không thể thu hồi một yêu cầu trước đó đã gửi; audit cuối lượt kiểm cả lịch sử.
5. Controller, card generator và reviewer dùng cùng bản đã che. Citation giữ ID và số dòng, nhưng quote là **bản chiếu**, không được gọi là nguyên văn byte của source.
6. `report.private.json` ghi `citation_view`/`validation_scope`; raw VM output và raw observation vẫn riêng tư. Báo cáo hiển thị tiếp tục có lớp redaction độc lập. Công bố Git chỉ dùng receipt metadata đã chọn trường.

`output_sha256` luôn định danh output gốc. Hash riêng `model_projection.view_lines_sha256` định danh các dòng trong bản chiếu của observation đó; không dùng hai hash thay nhau. Khi kiểm ngữ nghĩa phải đối chiếu source ở VM hoặc observation riêng và tính đến literal đã bị che.

Typed operation chứa một đối số cần che bị loại khỏi bản xem; không sửa nội dung rồi giữ nguyên `fact_id` như thể hash vẫn đúng. Một helper được hai caller sử dụng vẫn phải giữ hai ngữ cảnh gọi, dù cùng dẫn đến một hàm đích.

## Giới hạn

- Đây là detector theo mẫu, không chứng minh mọi secret đã được tìm thấy. Chuỗi mã hóa, tên biến lạ, biểu thức ghép chuỗi và page thiếu một phần assignment có thể chưa được nhận diện.
- Literal ngắn dưới 4 ký tự chỉ được che ở ranh giới từ để không phá mọi identifier. Audit exact-substring loại các literal ngắn khỏi mẫu số và báo số bị loại.
- Nếu cùng observation có đủ các fragment của một dòng và nhận diện được literal, những fragment đó bị giữ lại khỏi nội dung mô hình. Chưa bảo đảm nhận diện khi fragment nằm ở các page chưa từng nhận chung.
- Tập literal/độ dài có trần; quá trần sẽ từ chối tiếp tục inference. Không thực thi expression trong mẫu.
- Bộ dò và phép audit dùng cùng họ pattern. Kết quả không phải phép đo recall của detector hay chứng nhận dữ liệu đủ an toàn để công bố.
- Nhật ký controller lịch sử chỉ lưu evidence cùng hash message; card request có full message. Audit phải ghi số request không có full message, để gate full-request là `null`, không tự suy thành đạt. Schema trong nhật ký hiện chỉ có hash khi được ghi.

## Kiểm chứng và cách chạy

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\scripts\Start-Lab.ps1
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
.\.venv\Scripts\python.exe scripts/verify_context_projection.py
```

Script cuối chạy lại unpack/disassembly/decoder thật trong VM và gửi ba truy vấn HTTP. Nó kiểm reconstructed-source hash, hai caller cùng nhận helper, card giữ cả hai, và một truy vấn chứa cấu hình đã được che. Đây là kiểm tích hợp công cụ, **chưa là run SLM**. [Receipt HTTP](../deliverables/real-demo-evidence/context-v3-projection-http-check.json).

Sau một lượt ReAct hoàn tất, đo nhật ký:

```powershell
.\.venv\Scripts\python.exe -m eval.projection_audit runs/<run-id> --output evidence/local/projection-audit.json
```

Script kiểm hash chain, hash các full-message sẵn có, số request/response chứa giá trị đã nhận diện, và tái tạo bản chiếu từ từng raw observation. Không in giá trị hay hash riêng của mật khẩu. Run lịch sử trước sửa có [baseline audit](../deliverables/real-demo-evidence/model-projection-v5-baseline-audit.json): 11 request-evidence còn literal nhận diện được, 2 phản hồi lặp literal. Các kết quả run mới được ghi trong STATUS sau khi kết thúc, không điền trước số đo.

## Nhật ký request đầy đủ và lượt chưa hoàn tất

Từ bản tích hợp thao tác `/8`, controller, generator, reviewer và replay đều ghi nguyên messages + schema + evidence đã chiếu bằng `record_model_request`; quá giới hạn 512.000 byte thì từ chối, không cắt ngầm. Đây là dữ liệu riêng tư dưới `runs/` hoặc `private/`, không đưa lên Git. Audit `/2` kiểm cả hash schema và chỉ trả gate full-request khi mọi request có đủ hai thành phần.

Audit chạy được cả khi chưa tạo báo cáo: các trường report để `null`, không thay bằng báo cáo rỗng rồi coi không có rò rỉ. [Lượt thiếu RAM](../deliverables/real-demo-evidence/model-projection-v8-incomplete-audit.json) đã kiểm đủ 14 request/schema; kết quả chỉ bao phủ ba literal detector đã nhận diện. [Chi tiết tích hợp](OPERATIONS_CONTEXT_V8.md).

Audit `/3` bổ sung trạng thái `no_detected_literals`: nếu không có literal đủ điều kiện hoặc detector bị giới hạn thì gate để `null`. Lượt .NET v8 có 49 request đủ message/schema nhưng không có literal nhận diện được; số hit bằng 0 không là bằng chứng detector đã tìm hết bí mật hoặc phép thử che dữ liệu đã pass.

## Việc tiếp theo

Tiếp tục giữ riêng mức bảo đảm của trang nguồn, message và schema. Khi mở rộng detector, thêm ca kiểm escaped/split/short/alias và kiểm lại trên dữ liệu thật. Việc che literal không giải quyết nhận định sai, thiếu chứng cứ liên hàm, ATT&CK, YARA hoặc các ngưỡng chấm của môn học.
