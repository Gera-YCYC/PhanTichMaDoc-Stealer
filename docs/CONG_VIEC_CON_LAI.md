# Backlog để hoàn thành sản phẩm đồ án

## Ưu tiên của nhóm

Nhóm phụ trách bằng chứng tiếp tục tìm thiếu sót ở hai tầng. Ở tầng công cụ, thử truy vấn tiếp theo dựa vào đối số và nơi gán kết quả của hàm phụ, rồi so với quy trình cố định trong cùng ngân sách. Ở tầng báo cáo, tách mệnh đề có chứng cứ về lời gọi và mệnh đề cần thêm chứng cứ về tác dụng. Ví dụ thực tế là câu tạo bản ghi Opera và câu về tham số mở provider. Đo trên ba mẫu hiện có và tập giữ riêng trước khi chọn bản demo mới. [Sáu đoạn đã thử và hai lỗi tự duyệt](THU_CHON_DOAN_CHUNG_CU.md)

Bản web đã chạy và chấm ba mẫu khác nhau trên cùng mã, model và cấu hình. Sau lọc, báo cáo phủ 35/97 mục và bỏ sót 62. Ưu tiên nhánh .NET. Trên Gomorrah, 14/29 mục bị bỏ sót thiếu dòng từ công cụ, còn 11/29 đã truy xuất đủ nhưng có dòng vắng ở bước tạo nhận định. Trên Mercurial, hai nhóm này lần lượt là 6 và 5 mục. Khi thử sửa, giữ ba lượt gốc, ngân sách truy vấn, nhãn và cách chấm để có đối chứng. [Bằng chứng của bản web](CHAM_BA_MAU_WEB.md)

Ba báo cáo Python hiện đã đối chiếu đủ 99 lượt nhận định với nguồn. Sau tự duyệt còn bỏ sót 16–17/36 mục mỗi lượt. Trong từng lượt, 7 mục thiếu dòng từ công cụ, 5–6 mục đã có đủ dòng tham chiếu trong cùng một yêu cầu nhưng báo cáo đầu chưa nêu đúng. Nhóm phụ trách truy xuất cần đo lại phần lấy dòng. Nhóm phụ trách báo cáo cần kiểm riêng phần ý nghĩa và số câu đúng bị tự duyệt loại. Giữ tập chấm độc lập cho lần nghiệm thu. [Đối chiếu theo từng giai đoạn](CHAM_BAO_CAO_WEB.md)

Ba lượt cùng cấu hình web trên mẫu Python đã đo được 71,05% nhận định lặp lại. Việc tiếp theo là đối chiếu các nhận định thay đổi, kiểm xem khác cách diễn đạt hay khác nội dung, rồi chạy lại phép đo trên mẫu giữ riêng cho cả hai định dạng. Giữ cách tính hiện tại để so sánh qua phiên bản. [Kết quả và ba mã lượt](WEB_DIEU_TRA.md#độ-ổn-định-của-ba-lượt-python)

Dùng demo web cục bộ trong buổi bảo vệ. Việc kỹ thuật tiếp theo là đo độ chính xác và bỏ sót của từng liên kết trên mẫu giữ riêng, xử lý thêm liên kết qua helper và xác minh verdict. Tiếp tục đo ổn định cùng bản agent ba lần, mở rộng kiểm thử injection trên cả hai định dạng và kiểm cài đặt trên máy thành viên khác. Nhóm có thể nhập nhận xét đã đối chiếu nguồn trong web, train ứng viên và so lại báo cáo đầu-cuối. Yêu cầu fine-tune chính Qwen vẫn chờ giảng viên làm rõ. [Hướng dẫn điều tra](WEB_DIEU_TRA.md)

Mục tiêu hiện tại là toàn bộ sản phẩm theo slide và đề xuất gốc; buổi 4 chỉ là mốc đã có bằng chứng tích hợp. Không dùng số tool hay unit test để suy ra chất lượng phân tích. Tài liệu bàn giao là Markdown kỹ thuật, không yêu cầu thông tin sinh viên.

Ưu tiên hiện tại là nâng độ phủ hành vi, kiểm ATT&CK và kiểm quan hệ giữa dữ liệu được thu và dữ liệu được gửi. Trên Python, bản v11 đạt F1 72,13% trên 36 mục. Ba câu có phần diễn giải tác dụng helper vượt quá trích dẫn. Đã có 40 mục .NET cho Gomorrah và 7 mục cho AgentTesla. Xem [điểm từng mẫu và cách chạy](DEMO_COVERAGE.md). Phép đo ổn định cần ba lượt trên **cùng mẫu**. Ba mẫu khác nhau phục vụ mốc buổi 6.

**Cập nhật parser v4 / card v10:** đã mở rộng copy/read/write/fetchall/DPAPI/MIME/TLS và có kiểm source/HTTP thật. V9 vẫn sai ở IOC biểu thức, nhãn lớp API thành tên hàm và tự duyệt loại câu đúng. Đã có profile34 đơn vị và mapping22 đơn vị prediction cho v9: raw P 77,27%, R 50%, F1 60,71%, sau lọc F1 52%. V10 giới hạn IOC literal và tách nhãn API,318 test đạt; chạy đầu-cuối bị guard RAM dừng, nên còn phải đo chất lượng/độ ổn định trên bản này. Xem [chi tiết và kết quả âm](OPERATIONS_CONTEXT_V9.md).

Ưu tiên thực hiện tiếp: (1) giữ nguyên chất lượng câu khi tăng độ phủ thao tác và nối luồng lấy dữ liệu → file → archive → gửi; (2) kiểm IOC/ATT&CK/verdict trên cả .NET và Python, lập normalized reference .NET; (3) chạy bản chốt trên ít nhất3 mẫu và3 lần lặp, sau đó10 cặp injection đủ exposure; (4) so ranker trước/sau train trong toàn agent, kiểm tái lập và chốt tài liệu. Các kiểm parser hay report trên chứng cứ đã thu không thay các lần chạy đầu-cuối này.

Report-stage v10 đã chấm đủ12 câu đúng nhưng chỉ15/34 đơn vị được phủ; sau reviewer còn11/34 vì loại nhầm SMTP/DPAPI. A01 cần nâng độ phủ ngoài giới hạn hai câu/đoạn mà không suy diễn; A02 cần xử lý false rejection và ATT&CK đang rỗng. Tránh chỉ tiếp tục sửa prompt để tăng số câu được model tự nhận là đúng. Kết quả này chưa đóng E01/E02/S02 và chưa đủ thay profile mặc định.

Đã có bước chấm cùng đơn vị: `eval/atomic_units.py` và29 đơn vị development Python. [Thử nghiệm thao tác](ATOMIC_REPORT_STAGE.md) cho thấy6/29 với8B,4/29 với7B; câu xuất ra đúng nhưng bỏ sót nhiều. Chưa đổi luồng demo. Phải mở rộng helper/dataflow, đọc/copy/fetch/write/MIME/TLS; thêm IOC/ATT&CK có bằng chứng và verdict; chuẩn hóa baseline v8 và .NET rồi mới so toàn hệ thống.

Báo cáo hành vi sau run `20261127T211223_9602dfdd` vẫn chỉ có Python 8/11 câu đủ căn cứ, tự duyệt còn4/6; .NET14/20. Cần tách nhãn thao tác nội bộ khỏi tên hàm source, hạn chế câu lặp từ card thiếu helper và xử lý false rejection đối với AES/SELECT/DPAPI có chứng cứ. 7B từng trả rỗng trên9card; việc chọn7B cho YARA không chứng minh profile báo cáo này đã đạt. Xem STATUS và OPERATIONS_CONTEXT_V8.

Nhánh .NET cùng bản core đạt 14/20 câu đúng và gọi 2 công cụ khác nhau; hợp hai nhánh có 5 công cụ thật, đã đủ phần số lượng >=4 trong rubric. Không đặt thêm ngưỡng 4 công cụ cho từng mẫu. Vòng điều phối còn dùng 15 lượt tìm kiếm, có từ khóa không hợp nhánh; cần phản hồi hit/no-hit rõ hơn, giữ ngân sách tổng hợp và gọi thêm metadata/IOC/DIE khi có ích cho chứng cứ. Read/search không được tính như backend phân tích độc lập. Chưa có ba mẫu trên revision này, chưa đo stability ba lượt, chưa có đủ mười cặp injection hợp lệ.

| ID | Phần việc | Trạng thái thực tế | Điều kiện đóng |
|---|---|---|---|
| D01 | Chốt tập .NET/Python và file sạch | 5 mẫu độc public development;39 file sạch gồm37 Microsoft và2 PyInstaller; chưa có positive holdout | Manifest phân vai development/validation/test rõ; không đổi dữ liệu đã xem thành holdout |
| D02 | Đáp án .NET độc lập với agent | Có 40 mục Gomorrah đối chiếu 46 dòng ILSpy, thêm bảy mục AgentTesla với nguồn tĩnh và quan sát công bố | Mở rộng các luồng còn thiếu, giữ hash/dòng, ghi riêng kết quả người chấm độc lập |
| D03 | Phân tích Python3.11 | Đã giải mã payload candidate 332 dòng PythonStealer; pycdc vẫn lỗi | Đối chiếu luồng dữ liệu và claim cuối; tiếp tục Luna; không coi literal decode là đầy đủ mọi mẫu |
| D04 | >=3 mẫu có nhật ký | Đạt trên coverage-8b với PythonStealer, Gomorrah và Mercurial. Có cả lượt AgentTesla rỗng để đối chiếu | Cùng source/model/config, đủ report và evidence |
| T01 | Detect It Easy | Đã chạy backend thật và được SLM chọn trên Gomorrah | Kiểm thêm mẫu Python và môi trường dựng mới sau thay đổi installer |
| T02 | FLOSS | Đã chạy thật; .NET dùng static-only | Không gọi static strings là CIL deobfuscation; kiểm native mode/timeout |
| A01 | Chọn chứng cứ và báo cáo hành vi | Parser API v3, context v3, card v8; đã có archive/attachment/SMTP và AES kèm binding. Còn nhãn parser thành tên hàm, card rời thiếu helper và field/biến bị nhầm | Có claim thực chất, atomic, dẫn chứng đủ; không suy vai trò đối số từ tên biến |
| A02 | Reviewer và ATT&CK | Có kiểm chuỗi căn cứ verdict v3; reviewer vẫn loại sai và giữ sai | Đối chiếu source, kiểm liên kết thu/gửi; nguồn MITRE; không coi tự gán vai trò là chứng minh dữ liệu |
| S01 | Unicode và kiểm dữ liệu tới model | Có kiểm nội dung thông điệp theo hash, tọa độ nguồn và phản hồi cùng pha. Receipt P06 cũ thiếu nội dung để xác nhận lại. | Lưu đầu vào riêng trong lab và kiểm lại từ nhật ký |
| S02 | Bộ injection | Đã chạy 40 lượt trên cùng 10 cặp có tên tệp ẩn nhãn. Cả 10 cặp mỗi chế độ đủ chứng cứ. Bật chặn có 3/10 đầu vào model còn nguyên văn thử. | Kiểm trên bộ 12 tệp đa định dạng của đề xuất và cấu hình chốt. Kiểm độ đúng của cả bản đối chứng, ghi riêng kết quả theo hướng đổi verdict. |
| Y01 | Tập YARA thật | V3: 5 độc development, 39 sạch gồm 37 Microsoft và 2 PyInstaller; hash/nguồn/nhãn có lock | Đã đủ số file sạch dự kiến30–50; nếu muốn nói khả năng tổng quát hóa cần positive mới và thêm ứng dụng/họ độc lập |
| Y02 | Sinh và đo YARA | 7B/8B cùng bản: 5/5 độc, 0/39 sạch; replay độc lập khớp. Ngưỡng đạt trên corpus công bố | Giữ phạm vi development và luật theo bản build; kiểm rename/repack và tích hợp với báo cáo cuối. Kết quả âm v1 1/38 vẫn giữ |
| TR01 | Dữ liệu train | Corpus 117 anchor cấu trúc có provenance; chưa human review | Mở rộng dữ liệu/nhãn kiểm độc lập, giữ split; không giả người review |
| TR02 | Huấn luyện thật | Ranker CPU đã train; SLM chưa train; loại train GV chưa rõ | Hồ sơ ranker đã có; loại train theo GV còn mở |
| TR03 | So baseline với sau train | Một cặp AgentTesla cùng source/config. F1 trong 7 mục là 33,33% theo thứ tự dòng và 36,36% khi dùng ranker. Cả hai phủ 2/7 mục | So cùng bản/tools/config trên benchmark độc lập, chất lượng và chi phí |
| E01 | Bảng đúng/sai/bịa/bỏ sót | Đã chấm 87 câu thô trên ba mẫu coverage-8b. Có điểm trước/sau lọc, F1 riêng IOC + ATT&CK và mã mục bỏ sót | Chuẩn hóa prediction cùng đơn vị reference; mở rộng corpus; giữ raw/rejected; nhãn source-audit chưa human review |
| E02 | Stability | Đã đo cùng ba lượt guided-8b trên AgentTesla. Có 4/28 nhận định trùng, đạt 14,29%. Cả ba verdict đều inconclusive | Đạt ít nhất 80% trên cấu hình chốt và đối chiếu các câu đổi nội dung |
| E03 | Tài nguyên và so phương án | V8 8B: Python 484,7 s, .NET 503,5 s; có một lượt khác ngắt RAM. 7B chạy 162,2 s nhưng report rỗng | Ghi phạm vi đo; bổ sung peak và so cùng revision/config; không tính run dở/report rỗng là phân tích đạt |
| R01 | Tài liệu kỹ thuật | Đang cập nhật theo sản phẩm | Thiết kế, cài/chạy, luồng, dataset, training, đánh giá, giới hạn |
| R02 | Tái lập máy khác | Đã dựng VM mới trên cùng host ở bản cũ | Kiểm bản installer mới; máy vật lý khác chưa được xác nhận |

## Phần nhóm có thể chia nhau

Ngày 28/11, v13 đã bổ sung trích dẫn liền mạch và quét YARA ngay sau phần phân tích. Trên Mercurial, C21 đủ căn cứ cho T1539. Ưu tiên tiếp theo của nhánh .NET là phân biệt địa chỉ tài nguyên hiển thị với đích truyền, giữ ngữ cảnh hàm khi nhiều đoạn mã cạnh tranh vị trí trong prompt. Của nhánh Python là kiểm luồng SMTP và chạy lại cùng bản v13. Cả nhóm cần chốt hồ sơ tham chiếu độc lập trước khi xem đầu ra của bộ kiểm cuối. [Bảng chấm mới](../deliverables/real-demo-evidence/20261128T012820_c485ff68/review.md).

| Vai trò | Việc còn lại | Bằng chứng để bàn giao |
|---|---|---|
| Phân tích .NET | Rà các câu thiếu căn cứ trên Gomorrah và Mercurial. Đối chiếu lời gọi, thân hàm và dữ liệu truyền cho hàm. | Bảng nhận định có ID, số dòng, nhãn và danh sách IOC đã che giá trị nhạy cảm. |
| Phân tích Python | Kiểm lại đường đi từ dữ liệu đã thu đến tệp đính kèm SMTP, bổ sung phần bỏ sót trên PyInstaller. | Báo cáo có trích dẫn liên kết từng bước và kết quả riêng của pycdc/pycdas. |
| Đánh giá và an toàn | Chạy các cặp đối chứng với guard bật/tắt. Ghi cả ca model chưa nhận được dòng thử. Đề xuất gốc có 12 file và yêu cầu đa dạng vị trí chèn. | Tử số, mẫu số, hash thông điệp, verdict trước/sau và số ca chưa đánh giá được. |
| Tích hợp và demo | Chạy lại trên máy nhóm, đối chiếu hash model, checkpoint, nguồn VM và nhật ký. Trình diễn một lần chạy trực tiếp. | Run ID, trạng thái thực, bảng điểm cùng phiên bản, hồ sơ huấn luyện và kết quả tái lập. |

Mỗi thành viên có thể lấy một vai trò theo phân công của nhóm. Trình tự nghiệm thu là đối chiếu mã nguồn, chốt phiên bản, chạy cùng cấu hình trên bộ mẫu, tính điểm và rà lại kết luận.

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

Lịch sử kiểm injection đã được sửa cách diễn giải: 9/10 trước đây chỉ chứng minh payload tới observation; audit v2 yêu cầu model_request nên **0/10 lịch sử đủ điều kiện**, không phải 0% bị lừa. Kiểm lại P06 theo nội dung thông điệp thực tế cho kết quả chưa đủ chứng cứ.

Tài liệu/slide/video và vấn đáp trong slide gốc được giữ để nhóm biết yêu cầu môn học. Theo phạm vi sản phẩm người dùng chốt, không chờ tên/MSSV, phân công cá nhân hoặc hoạt động trên lớp để tiếp tục xây phần mềm.

Không sửa trạng thái thành hoàn tất nếu thiếu thực nghiệm. Nếu train không cải thiện, công bố kết quả âm và giữ baseline; không tạo số loss hoặc checkpoint giả.
