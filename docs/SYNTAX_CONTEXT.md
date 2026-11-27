# Ngữ cảnh hàm và lời gọi trong phân tích tĩnh

## Mục đích

Một đoạn quanh từ khóa có thể chỉ chứa lời gọi `send_email(...)`, trong khi phần tạo attachment và SMTP nằm ở hàm khác. Báo cáo không được biến tên hàm hoặc tên biến thành bằng chứng đã gửi dữ liệu. Bản mới bổ sung các đoạn liên quan để SLM có thể đối chiếu tham số, phép gán, giá trị trả về và API thực sự được gọi.

Đây là bước điều hướng source trong VM, không phải thực thi mẫu và chưa phải bộ phân tích luồng dữ liệu có kiểm chứng kiểu/alias. SLM vẫn chọn `search_evidence`; parser bổ sung ngữ cảnh cho thao tác tìm kiếm đó. Không cộng parser thành một công cụ phân tích độc lập để làm đẹp số tool.

## Cách xây dựng

Backend ban đầu `tree-sitter-context/1` dùng ba gói đã khóa: tree-sitter 0.25.2, tree-sitter-python 0.25.0, tree-sitter-c-sharp 0.23.5. Bản `/2` giữ dependency này và đổi cách chọn helper như mục dưới. Linux wheels được khóa URL/kích thước/SHA256 trong `config/setup-assets.lock.json`. Host tải dependency, VM cài offline vào `/opt/stealer-lab/deps`; VM không cần Internet. Giao diện Parser/Language theo [tài liệu chính thức py-tree-sitter](https://github.com/tree-sitter/py-tree-sitter); [grammar C#](https://github.com/tree-sitter/tree-sitter-c-sharp) cung cấp cây cú pháp, không phải Roslyn semantic model.

1. Ghép lại các dòng nguồn từ record bất biến trong VM, kể cả dòng dài đã tách thành đoạn 600 ký tự. Ánh xạ từ dòng nguồn sang dòng evidence vẫn được giữ.
2. Với source được decoder thu, chỉ nhận đúng một candidate; hai dòng provenance được để trống trong bản nhìn để parse nhằm giữ tọa độ. Nhiều candidate không được nối như cùng một module.
3. Tìm hàm, lời gọi trực tiếp và đích có tên duy nhất. Với C#, cho phép dạng `TênLớp.HàmStatic(...)` khi khớp khai báo, hoặc `this.Hàm(...)` cùng lớp; không tự bind `obj.Hàm(...)` khi chưa biết kiểu. Overload trùng tên không được tự chọn.
4. Ưu tiên caller của hàm chứa hit tìm kiếm. Trả đoạn quanh lời gọi, đoạn đầu/thân callee và tối đa một helper gần đó. Hàm dài có cờ `callee_complete=false`.
5. Trả đúng các dòng gốc, không viết lại source. Quan hệ mang nhãn `unique_name_local_call_candidate_not_semantic_binding` để thể hiện giới hạn.
6. Host áp dụng guard lên toàn bộ dòng mới. Nhánh báo cáo `evidence-cards/4` gom 2–3 khoảng dòng đã nhận vào một mục chứng cứ; nếu thiếu dòng hoặc một đoạn bị che thì không tạo mục liên kết đó. Từng khoảng phải khớp nguyên văn khi kiểm citation.

Các mục liên kết ưu tiên đa dạng hàm đích, tối đa bốn mục trong ngân sách báo cáo hiện tại. Hai phần source được hiển thị thành SECTION riêng, không ghép thành một đoạn liên tục giả. Bộ duyệt nhận cùng các SECTION mà bộ sinh câu đã nhìn thấy. Cờ cấu hình vẫn là `evidence-cards-v1` để tương thích; kết quả mới ghi phương pháp `/4`.

## Giới hạn tài nguyên và tính đúng

- Worker cố định chạy trong VM, timeout 20 giây, giới hạn không gian địa chỉ 1,5 GB, output tối đa 100.000 byte. Nó chỉ parse source; không import, eval hoặc chạy code mẫu.
- Tối đa 2 MB source, 16.000 dòng evidence, 200.000 node khi duyệt cây. Một khoảng citation không vượt 40 dòng/4.800 ký tự; tổng nội dung một mục báo cáo không vượt ngân sách 4.600 ký tự hiện tại.
- Tìm kiếm literal vẫn trả kết quả khi parser thiếu dependency hoặc lỗi; trường `syntax_context.status=unavailable` ghi rõ. Không có link giả trong trường hợp đó.
- Kiểu động, alias, shadowing tên, reflection, delegate và gọi hàm ảo chưa được giải quyết. Một link cú pháp không đủ để nói dữ liệu nhạy cảm đã được truyền từ nguồn sang đích. Các thao tác vẫn cần chứng cứ cụ thể và chấm độc lập.
- Hash bản nhìn source dùng cho parse khác hash mẫu và có thể khác hash payload decoder vì cách giữ các dòng provenance trống. Receipt giữ cả hash output gốc để đối chiếu, không thay thế hash mẫu.

## Kiểm chứng hiện có

### Bổ sung thân helper ở bản v2

Đối chiếu Python v5 cho thấy model viết về tác dụng của `decrypt_password` khi citation chỉ có lời gọi. Bản v1 thường chọn một helper song song ở hàm cha làm khoảng thứ ba, dẫn đến lặp nội dung lấy mật khẩu/thẻ và vẫn thiếu implementation được nhắc tới.

Bản v2 ưu tiên hàm con có đối số được gọi trong phần callee đã hiển thị, nếu tên đích duy nhất và toàn thân không quá 35 dòng source. Chỉ thêm một mức, không mở rộng đệ quy. Hàm con không đối số không đẩy mất helper chuẩn bị dữ liệu ở caller; nếu không tìm được dependency phù hợp thì giữ cách chọn neighbor. Vẫn tối đa ba khoảng, ngân sách ký tự giữ nguyên; thiếu chỗ thì bỏ khoảng tùy chọn, không cắt giả thành thân đầy đủ.

Trường `related_context_kind` phân biệt `callee_dependency_candidate_not_dataflow_proof` và `caller_neighbor_candidate_not_dataflow_proof`. `related_call_line` ghi vị trí lời gọi tương ứng. Đây vẫn là ứng viên cú pháp, chưa giải alias/shadowing hoặc chứng minh việc truyền dữ liệu.

[Kiểm source thật trong VM](../deliverables/real-demo-evidence/dependency-context-real-source-check.json) xác nhận cả `get_login_data` và `get_credit_cards` nhận đủ thân helper ở dòng evidence 69–75, nguyên văn so với record đã khóa hash. Bốn test bổ sung kiểm ưu tiên dependency, giữ neighbor khi child không đối số, recursion và thân quá dài. Tổng 172 test phần mềm đạt trên Windows tại bản này. Kết quả độ chính xác cần run SLM mới và source audit riêng; không suy tăng Precision từ việc thêm source.

### Bằng chứng bản v1

[Kiểm trên source thật đã thu trong VM](../deliverables/real-demo-evidence/syntax-context-real-source-check.json) nhận diện 14 hàm Python/19 lời gọi ứng viên và 130 hàm C#/158 lời gọi ứng viên; không có lỗi parse trong hai record này. Tất cả dòng trả về khớp record gốc. Trường hợp Python ghép được lời gọi gửi email, thân hàm gửi và helper tạo archive; trường hợp .NET có callee dài nên ghi rõ chưa đầy đủ.

Đó là kiểm backend trên evidence lưu sẵn, không phải một lần ReAct mới. Lượt agent mới phải có model request, thao tác tool, context_links và báo cáo cùng revision trước khi được dùng làm demo. Bộ kiểm thử phần mềm hiện có 131 ca trên Windows, bao phủ cả dispatcher gọi worker thật trên fixture vô hại; số này không phải chất lượng trên malware.

## Máy thành viên đã có VM

Trong thư mục dự án, sau khi lấy source mới:

```powershell
.\scripts\Start-Lab.ps1
.\.venv\Scripts\python.exe scripts/install_syntax_tools.py
.\.venv\Scripts\python.exe scripts/sync_vm.py
```

`Setup-Team.ps1` cho VM dựng mới đã dùng lock cập nhật, nên bootstrap sẽ giải nén cả ba wheel vào dependencies. Không chạy lại provisioning hoặc revert snapshot của VM đang giữ mẫu/chứng cứ. `verify_syntax_context.py` dùng ID của các run phát triển cục bộ; thành viên mới không có journal/record đó thì cần tự chạy để tạo evidence của mình.

Phép thử Qwen3 cần model candidate cục bộ theo [MODEL_COMPARISON](MODEL_COMPARISON.md); model mặc định và Release vẫn giữ baseline 7B. Kết thúc đợt chạy dùng `Stop-Lab.ps1` để trả RAM/VRAM.
