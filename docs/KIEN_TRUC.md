# Kiến trúc, phạm vi và quyết định thiết kế

## Phân tích tĩnh trong VM

Host chạy controller Python và Ollama tại `127.0.0.1:11435`. Tool server tại `192.168.56.101:8765` chỉ nhận client `192.168.56.1` có bearer token. Mỗi yêu cầu gồm tool hợp lệ và tên mẫu nằm trong thư mục VM. HTTP này chỉ dùng trên mạng host-only riêng, không phải giao thức triển khai Internet.

VM Ubuntu 24.04 dùng 2 GB RAM/2 vCPU. File mẫu là `root:analyst` mode 0440. Service chạy dưới tài khoản analyst, giới hạn systemd và không có chức năng shell/upload/chạy mẫu. Mỗi lệnh backend có argv cố định từ cấu hình tin cậy. PyInstaller parser và pycdc/pycdas chạy trong subprocess có giới hạn thời gian, output, bộ nhớ và nhóm tiến trình. Đây là giảm thiểu rủi ro parser, không chứng minh không có lỗ hổng.

Kiểm tra host-only, không default route, chia sẻ folder/clipboard tắt được lưu trong `evidence/local/lab-verification.json`. Snapshot `clean-tools-installed-20261127` được tạo trước khi thêm extension/public samples. Không revert snapshot này trong lúc giữ dữ liệu mới; muốn phục hồi phải lập kế hoạch sao lưu chứng cứ trước.

## Vòng ReAct

### Chạy ở máy thật hay máy ảo?

Lệnh `Run-Demo.ps1`, chương trình điều phối và Ollama chạy ngay trên Windows máy thật. GPU của máy thật phục vụ SLM; máy ảo không cần một GPU riêng. Cửa sổ PowerShell và báo cáo có thể được mở ở host để demo. Việc này không đồng nghĩa mở mẫu hoặc chạy công cụ phân tích mẫu ở host.

VM là phòng phân tích: chứa mẫu, ILSpy/pefile/pyinstxtractor/pycdc/pycdas/decoder, kho chứng cứ đầy đủ và dịch vụ công cụ. Hai phía trao đổi tên công cụ, sample ID, JSON và đoạn chứng cứ hữu hạn qua mạng host-only. Không có việc đưa binary vào Ollama. Cả hai máy ở cùng laptop, không cần mua hai máy vật lý.

Trong đồ án này vẫn cần VM: ảnh 10 yêu cầu không cho agent chạy lệnh phân tích ngoài VM cô lập; ảnh 9 gắn VM và xử lý dữ liệu với tiêu chí an toàn. Đọc tĩnh cũng sử dụng parser trên dữ liệu không tin cậy. Bản sản phẩm hiện tại không có chế độ chạy trực tiếp parser/mẫu thật trên host để thay VM. `Stop-Lab.ps1` dừng runtime sau demo, trả RAM/VRAM mà không xóa trọng số hoặc đĩa VM.

1. Preflight model/VM và ghi phiên bản mã nguồn.
2. SLM chọn tool bằng JSON schema, kèm mục đích ngắn.
3. Controller kiểm tên mẫu, tool, tham số và giới hạn bước.
4. VM tính SHA256, chạy backend tĩnh, trả ID và dòng chứng cứ có phân trang.
5. Host gắn nhãn dữ liệu không tin cậy, che mẫu câu prompt injection được nhận biết, gửi đặc trưng có giới hạn lại cho SLM.
6. SLM chọn tool tiếp theo hoặc gửi report. Controller kiểm dẫn chứng và giữ những nhận định bị loại trong log.

Agent không có quyền tạo shell command hoặc tải tool mới. Model không thấy binary. Raw output đầy đủ lưu tại VM; host nhận excerpts/đặc trưng. Tìm kiếm chỉ là truy vấn chuỗi cố định trong kho chứng cứ.

## Python và .NET

Nhánh .NET dùng pefile xác nhận CLR rồi ILSpy CLI. Một bản snapshot input được gắn hash để tránh đầu vào thay đổi giữa các bước. Dịch ngược thành công không bảo đảm logic runtime đã được hiểu.

Nhánh Python source dùng `ast.parse`, không import source. PyInstaller dùng adapter giới hạn dựa trên pyinstxtractor để trích entry scripts. Không thực thi bytecode, không tự giải mã payload bằng `exec`. pycdc phục hồi source nếu không có diagnostics. pycdas là phương án đọc opcode/constants, có tool ID riêng và giới hạn rõ ràng; nó không biến source recovery lỗi thành thành công.

[Decompyle++ upstream](https://github.com/zrax/pycdc) mô tả pycdc và pycdas là hai đầu ra khác nhau. Bản đang dùng được build từ commit `b4289760970dbc399684f1e155ec6d1ea1cc787e`; việc có hỗ trợ một version trên lý thuyết không thay thế kiểm thử mẫu cụ thể.

## Kiểm trích dẫn và đánh giá

Mỗi claim giữ `evidence_id`, line và quote. Controller kiểm đúng mẫu, đúng nguồn thành công, quote đúng dòng. Nó không tự xác minh quan hệ nhân quả. Lớp semantic reviewer dùng cùng SLM là một lần kiểm tra heuristic; đã có ca loại sai metadata đúng, nên không dùng kết quả đó làm ground truth.

Nhánh thử [báo cáo theo đoạn chứng cứ](EVIDENCE_CARDS.md) bổ sung `end_line`, kiểm từng dòng của khoảng liên tục và tách tạo/kiểm từng nhận định. `finalize` chỉ chuyển pha trên controller, không được đếm như một công cụ thật. Cấu hình legacy và log cũ vẫn được giữ để đối chiếu; ưu thế chất lượng phải đo thực nghiệm.

Nhận định do agent tạo, nhận định bị controller/reviewer loại và quan sát thuần từ công cụ cần được chấm riêng. Không bỏ các claim bịa khỏi mẫu số để nâng Precision hoặc hạ hallucination. `inconclusive` trên malware được tính là verdict chưa đúng khi đánh giá verdict accuracy.

## YARA

Model đề xuất tên luật, literal selectors và quan hệ all/any. Controller render cú pháp YARA xác định, lưu file chính xác, compile bằng yara-python và test trong VM. Đây là luật sinh từ đặc tả SLM, không phải khẳng định model tự viết toàn bộ cú pháp YARA tự do.

Tập train và holdout là hai manifest cố định. Mẫu holdout không được đưa vào vòng tinh chỉnh. Bộ marker fixture hiện có kết quả holdout không đạt; lần dùng tiếp chỉ được gọi là tập development đã biết kết quả. Cần bộ holdout mới để đo tổng quát hóa sau khi sửa luật.

## Khác biệt với đề xuất gốc

| Nội dung | Đề xuất/slide | Bản hiện tại và lý do |
|---|---|---|
| VM | Windows/FLARE-VM | Ubuntu tĩnh để vừa RAM 12 GB; chưa có phân tích động Windows |
| Model | SLM 7B hướng 6 | Qwen2.5 Coder 7B, Q4_K_M trên C; model 1.5B D giữ nguyên |
| Mẫu | I .NET 5.632 B, J ~8 MB | Người dùng xác nhận tự tìm public; nguồn/hash riêng, không ép kích thước |
| Chuỗi/định dạng | Có DIE/FLOSS trong đề xuất | Đã có DIE 4.0.0/FLOSS 3.2.0 trong VM; .NET chỉ static strings; strings riêng giữ UTF-8 |
| Python giải mã | pyinstxtractor + pycdc | Cả hai có thật; ca Python3.11 phát diagnostics, pycdas chỉ là fallback opcode |
| Nhật ký suy nghĩ | Thought/Action/Observation | Lý do hành động ngắn, action/observation thật, không xuất nội bộ suy luận |

## Ranh giới kết quả

Unit test kiểm công thức và chốt kỹ thuật. Fixture kiểm toolchain. Log real-model chứng minh model có gọi backend. Hash chain chứng minh tính nhất quán nội bộ của file log, không phải chữ ký của giảng viên. Chỉ bảng chấm trên bộ public và file sạch đã chốt mới là dữ liệu để đánh giá các ngưỡng môn học.
