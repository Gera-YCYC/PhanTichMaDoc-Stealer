# Backlog để hoàn thành sản phẩm đồ án

Mục tiêu hiện tại là toàn bộ sản phẩm theo slide và đề xuất gốc; buổi 4 chỉ là mốc đã có bằng chứng tích hợp. Không dùng số tool hay unit test để suy ra chất lượng phân tích. Tài liệu bàn giao là Markdown kỹ thuật, không yêu cầu thông tin sinh viên.

| ID | Phần việc | Trạng thái thực tế | Điều kiện đóng |
|---|---|---|---|
| D01 | Chốt tập .NET/Python và file sạch | Có 5 mẫu public với hash; đều đã dùng phát triển | Manifest phân vai development/validation/test rõ; không đổi dữ liệu đã xem thành holdout |
| D02 | Đáp án .NET độc lập với agent | Đang đối chiếu ILSpy và phân tích nguồn | Liên kết luồng lấy dữ liệu → lưu/xử lý → gửi; source hash/dòng; nhãn có provenance |
| D03 | Phân tích Python3.11 | Đã giải mã payload candidate 332 dòng PythonStealer; pycdc vẫn lỗi | Đối chiếu luồng dữ liệu và claim cuối; tiếp tục Luna; không coi literal decode là đầy đủ mọi mẫu |
| D04 | >=3 mẫu có nhật ký | Đã có log lịch sử; cần chạy lại bản chốt | Cùng source/model/config, đủ report và evidence |
| T01 | Detect It Easy | Đã chạy backend thật và được SLM chọn trên Gomorrah | Kiểm thêm mẫu Python và môi trường dựng mới sau thay đổi installer |
| T02 | FLOSS | Đã chạy thật; .NET dùng static-only | Không gọi static strings là CIL deobfuscation; kiểm native mode/timeout |
| A01 | Chọn chứng cứ và báo cáo hành vi | Đã ghép caller/callee bằng parser trong VM; còn thiếu dependency sâu, lẫn SQL/giải mã và ý nghĩa đối số | Có claim thực chất, atomic, dẫn chứng đủ; không suy vai trò đối số từ tên biến |
| A02 | Reviewer và ATT&CK | Có kiểm chuỗi căn cứ verdict v3; reviewer vẫn loại sai và giữ sai | Đối chiếu source, kiểm liên kết thu/gửi; nguồn MITRE; không coi tự gán vai trò là chứng minh dữ liệu |
| S01 | Unicode và kiểm exposure | Đã sửa; P06 guard on/off có request thật | Giữ byte offset, log evidence thực đã gửi, không đếm payload bị mất |
| S02 | Bộ injection | P06 hợp lệ; bộ lịch sử không đủ request provenance | >=10 ca đủ exposure, on/off, cả hai chiều; thống kê mẫu số chính xác |
| Y01 | Tập YARA thật | Chưa có tập độc/lành chốt | Positive public và clean độc lập; khóa holdout trước tuning |
| Y02 | Sinh và đo YARA | Compile/test thật có; marker holdout lịch sử TPR=0 | Agent sinh đặc tả, replay độc lập; TPR>=90%, FPR=0 trên corpus công bố |
| TR01 | Dữ liệu train | Corpus 117 anchor cấu trúc có provenance; chưa human review | Mở rộng dữ liệu/nhãn kiểm độc lập, giữ split; không giả người review |
| TR02 | Huấn luyện thật | Ranker CPU đã train; SLM chưa train; loại train GV chưa rõ | Hồ sơ ranker đã có; loại train theo GV còn mở |
| TR03 | So baseline với sau train | Có hit@1 trên subset candidate; chưa đủ F1 agent | So cùng bản/tools/config trên benchmark độc lập, chất lượng và chi phí |
| E01 | Bảng đúng/sai/bịa/bỏ sót | Đã chấm đủ câu thô Python v1/v2/v3/v4; v4 Precision 50% trên 16 câu; chưa đủ recall/toàn corpus | Chốt đơn vị fact và ghép đầy đủ; giữ raw/rejected; nhãn source-audit chưa human review |
| E02 | Stability | Thử lịch sử chưa đạt | 3 run cùng sample/model/source/config; intersection/union>=80% |
| E03 | Tài nguyên và so phương án | Cache 256 MiB giúp 8B chạy lại; Python v3 hoàn tất 458,6 s, min free RAM 534 MB giữa request | Ghi phạm vi đo; bổ sung peak và so cùng revision/config; không tính run dở là hoàn tất |
| R01 | Tài liệu kỹ thuật | Đang cập nhật theo sản phẩm | Thiết kế, cài/chạy, luồng, dataset, training, đánh giá, giới hạn |
| R02 | Tái lập máy khác | Đã dựng VM mới trên cùng host ở bản cũ | Kiểm bản installer mới; máy vật lý khác chưa được xác nhận |

## Các ngưỡng phải giữ nguyên

| Tiêu chí | Ngưỡng theo slide | Cách tính/điều kiện |
|---|---|---|
| Precision | >=0,8 | Đúng/(Đúng+Sai+Bịa) |
| Recall | >=0,7 | Đúng/(Đúng+Bỏ sót) |
| F1 | >=0,75; xuất sắc >=0,8 | 2PR/(P+R) |
| Verdict | 100% mẫu lab công bố | Inconclusive không tính đúng cho nhãn lành/độc |
| Hallucination | <=5% | Bịa/tổng nhận định; báo cả raw và sau lọc |
| Grounding | >=90% | Có chứng cứ đúng, không chỉ quote tồn tại |
| Stability | >=80% | 3 lần cùng điều kiện |
| YARA | TPR>=90%, FPR=0 | Corpus có positive/negative riêng, mẫu số công bố |
| Injection | 0%, >=10 file thử | Cặp đủ exposure và hoàn tất; số thiếu bằng chứng là null/unevaluable |
| Kỹ thuật | >=4 công cụ thật cho mức xuất sắc | Phiên bản/backend/input/output hash và log |
| Hiệu quả | Ghi đủ và so phương án | Bước, lỗi, thời gian, token, RAM/VRAM, API cost |
| Training bổ sung | Thấy quá trình train thật | Loại train chưa rõ; không dùng tải model/prompt thay training |

Các bước ưu tiên: cải thiện hành vi/IOC ở cả hai nhánh → lập đáp án độc lập → train/evaluate → YARA/injection/stability → tái lập và tài liệu chốt. Dữ liệu đã xem dùng để sửa chương trình phải mang nhãn development.

Sau v4, việc tiếp theo của A01/A02 là biểu diễn rõ từng thao tác và đầu vào/đầu ra có dẫn chứng, đặc biệt API trả phản hồi so với file gửi đi, query so với helper giải mã. Điều hướng cú pháp đã có nhưng chưa phải semantic/dataflow engine. Không tiếp tục coi tăng số câu hoặc tăng tỷ lệ câu được reviewer giữ là cải thiện. Cần xử lý cả phần che thông tin đăng nhập nhúng trong source và bị model nhắc lại: raw journal/report luôn để cục bộ; bản công khai chỉ xuất metadata theo danh sách trường cho phép.

Cập nhật sau thí nghiệm báo cáo đoạn: đã có cấu hình cache 256 MiB giúp 7B/8B hoàn tất mà không tích lũy nhiều GiB cache. A01 cần giữ vị trí hit của tìm kiếm khi tạo claim để model không chỉ mô tả các dòng đầu đoạn. A02 cần chặn import-only bị gán behavior và đo cả false rejection (SQLite/ghi file có chứng cứ) lẫn false acceptance. Qwen3 có một run Python thật 4 tool/verdict malicious nhưng còn các lỗi này, chưa đủ thay default hoặc đóng ANALYSIS/TRUST. Nhánh báo cáo đoạn hiện chưa bao phủ IOC/ATT&CK/YARA đầy đủ; không được bỏ các đầu ra đó khỏi tiêu chí cuối.

Lịch sử kiểm injection đã được sửa cách diễn giải: 9/10 trước đây chỉ chứng minh payload tới observation; audit v2 yêu cầu model_request nên **0/10 lịch sử đủ điều kiện**, không phải 0% bị lừa. Các run P06 mới có bằng chứng riêng.

Tài liệu/slide/video và vấn đáp trong slide gốc được giữ để nhóm biết yêu cầu môn học. Theo phạm vi sản phẩm người dùng chốt, không chờ tên/MSSV, phân công cá nhân hoặc hoạt động trên lớp để tiếp tục xây phần mềm.

Không sửa trạng thái thành hoàn tất nếu thiếu thực nghiệm. Nếu train không cải thiện, công bố kết quả âm và giữ baseline; không tạo số loss hoặc checkpoint giả.
