# Goal và điều kiện nghiệm thu

## Mục tiêu sản phẩm cập nhật ngày 28/11/2026

Sản phẩm bàn giao là web chạy trên máy thật, một agent ReAct dùng Qwen cục bộ và các công cụ đọc tĩnh trong VM. Điều kiện nghiệm thu cho từng quan hệ là có bằng chứng tại nơi tạo, nơi dùng và cách dữ liệu đi giữa hai vị trí. Khi thiếu một phần, agent tìm thêm trong ngân sách đã đặt, lưu kết quả từng lần, rồi giữ trạng thái còn thiếu nếu chưa xác minh được. Mục A09 trên Python hiện có phép kiểm hai phía và bản đồ mở được đúng nguồn. Các chỉ tiêu chấm trên toàn mẫu, hai định dạng và dữ liệu giữ riêng vẫn là mục tiêu chung. [Kết quả A09 và phép đo toàn báo cáo](KIEM_TRA_DOI_SO.md)

Đã đưa phép thử tách mệnh đề vào màn hình đối chiếu và đo đủ các quyết định trên bảy câu thật. Mục tiêu còn mở là tìm bằng chứng nối trường đầu vào với nơi sử dụng, kiểm soát suy diễn thiếu căn cứ rồi đo tác động lên báo cáo cuối của cả Python và .NET. [Số liệu và ca chưa giải quyết](KIEM_TUNG_Y.md)

Đưa việc kiểm chứng vào thao tác demo. Từ bảng chấm, người dùng mở được câu gốc và dòng chứng minh của từng lượt. Bản hiện tại đã đo 3 lượt Python với cùng model, mẫu và mã lõi. 28/40 nhận định trùng nhau, dưới ngưỡng 80% của giảng viên. Mốc kế tiếp là phục hồi các ý đúng bị loại cùng câu ghép, đo lại cả hai định dạng và đối chứng trên tập giữ riêng. [Ba lượt và tiêu chí chấm](DO_ON_DINH_BAN_DIEU_TRA.md)

Nhóm ưu tiên hai chức năng đi cùng nhau. Khi một liên kết còn thiếu, agent phải chọn phép kiểm dựa trên kết quả vừa đọc. Người dùng bấm được vào chính đường nối đó để mở bằng chứng và hỏi tiếp. Đích ghi dưới thư mục nén đã được kiểm trong một ca Python thật. Điều kiện nghiệm thu tiếp theo là xác minh dữ liệu còn nguyên đến điểm sử dụng và lặp lại phép đo trên tập giữ riêng. Số liệu đầy đủ vẫn gồm cả chất lượng toàn báo cáo, tuyên bố thiếu căn cứ và chi phí gọi công cụ. [Lượt thử và những mắt xích còn mở](DUONG_DAN_GHI_VA_NEN.md)

Mục tiêu nghiệm thu là người dùng có thể đi từ giả thuyết còn thiếu, qua hành động của agent trong VM, đến từng nhận định có nguồn và verdict đủ căn cứ. Bản web đã đưa liên kết vào báo cáo chính và đo tác động trên ba hồ sơ cố định. Mốc tiếp theo là chứng minh nguồn dữ liệu nhạy cảm đi tới bên gửi, đo lại độ phủ và verdict trên tập giữ riêng, rồi tái lập trên máy thành viên. [Bằng chứng và giới hạn hiện tại](DOI_CHIEU_DUONG_TRUYEN.md)

Khi agent gặp một lời gọi .NET còn thiếu phần thân, người dùng có thể để Qwen tự chọn vị trí để VM kiểm tra. Bản đồ cần mở được kết quả từng lượt và giữ trạng thái thiếu bằng chứng nếu chưa chứng minh được dữ liệu đi qua các bước. Đã đo phần đối chiếu hai thân hàm trên tập phát triển. Mục tiêu tiếp theo là xác minh luồng dữ liệu trên tập giữ riêng, sau đó chấm lại toàn báo cáo theo ngưỡng gốc. [Cách thử và giới hạn](DOI_CHIEU_THAN_HAM.md)

Đã nối việc tìm thêm dòng trong VM với phụ lục có thể mở và chấm từng câu trên web. Cấu hình kết hợp được thử trực tiếp trên hồ sơ .NET. Tiêu chí còn mở là chứng minh chất lượng của báo cáo hoàn chỉnh trên tập tách riêng và khả năng nối dữ liệu thu thập với dữ liệu gửi đi. [Phương pháp đối chứng và kiểm lại](PHU_LUC_DIEU_TRA_NET.md)

Đối chứng cố định/thích nghi phải ghi riêng số lần gọi VM, model, thời gian và mục tìm được. Đã đo cho cả việc tìm liên kết ban đầu và việc tìm tiếp trên hai báo cáo .NET. Điều kiện nghiệm thu cuối vẫn cần đo lại recall, F1 và verdict sau khi đưa nguồn mới vào báo cáo. [Đối chứng tìm tiếp](CHAM_BA_MAU_WEB.md#tìm-thêm-chứng-cứ-trong-vm-trên-hai-mẫu-net)

Web phải cho người phân tích truy ngược câu bị loại tới mã nguồn, yêu cầu đọc lại và kiểm tra lỗi của chính bộ duyệt. Chức năng này có hai lần bấm thật và bảng chấm hai phương án trên 13 câu. Mục tiêu chất lượng cuối vẫn tính trên báo cáo toàn mẫu. [Bằng chứng và phạm vi đo](DOC_LAI_NHAN_DINH.md)

Điều kiện nghiệm thu phần điều tra gồm theo dõi từng giả thuyết từ truy vấn tới trạng thái sau khi công cụ trả lời, mở được vị trí trích dẫn và phân biệt các câu đúng bị bộ duyệt loại. Hiện giao diện đã hiển thị các bước này. Chất lượng cuối vẫn chấm theo đáp án, verdict và ngưỡng trên slide. [Phép thử trên ba mẫu](THU_CHON_DOAN_CHUNG_CU.md)

Giữ nguyên tên đề tài và các ngưỡng giảng viên. Ưu tiên agent chủ động xác định phần bằng chứng còn thiếu, điều tra bằng công cụ thật trong VM và lập bản đồ để người phân tích kiểm từng liên kết. Sản phẩm bàn giao gồm giao diện web cục bộ nối agent, Qwen và VM, nhật ký thật, hỏi đáp có dẫn nguồn, tạo–kiểm–sửa luật YARA, nhãn có phiên bản cho ranker và thí nghiệm đối chứng với quy trình cố định. Đích xuất bản là repo nhóm Gera-YCYC/PhanTichMaDoc-Stealer. Khi bàn giao sản phẩm, dùng demo web trực tiếp. Quay video mới nằm ngoài phần việc người dùng giao. Các yêu cầu nộp bài trên slide vẫn được lưu nguyên trong tài liệu nguồn. [Cách chạy và phạm vi kiểm chứng](WEB_DIEU_TRA.md)

Nguồn có thẩm quyền: 12 ảnh slide và đề xuất gốc trong `docs/reference/`.

Trên bản web hiện hành đã có ba mẫu phát triển khác nhau với nhật ký, YARA, bảng chấm từng câu và kết quả gộp. Trong 97 mục tham chiếu, báo cáo sau lọc phủ 35. Các mốc còn mở tập trung vào chất lượng điều tra, verdict, phép thử độc lập và tái lập ngoài máy lab. [Nghiệm thu theo chỉ tiêu](CHAM_BA_MAU_WEB.md)

Ba lượt web trên mẫu phát triển Python đã được đối chiếu từng câu và từng mục bỏ sót. Đích chất lượng kế tiếp là tăng recall có dẫn chứng, giảm lỗi tự duyệt, đo lại theo cùng điều kiện ở cả hai định dạng và kiểm trên tập giữ riêng. [Bảng chấm bản web](CHAM_BAO_CAO_WEB.md)

Mốc kiểm chứng web ngày 28/11 đã có demo đầu-cuối, bản đồ và hỏi đáp có nhật ký, thí nghiệm YARA và phép đối chứng tìm liên kết. Trên ba lượt cùng cấu hình Python, độ ổn định nhận định đạt 71,05% so với ngưỡng 80%. Các bước nghiệm thu còn lại gồm chấm chất lượng bản hiện hành, đo trên mẫu giữ riêng, mở rộng phép thử injection và kiểm cài đặt trên máy thành viên. [Bảng tiến độ](STATUS.md) · [Phân công kỹ thuật còn lại](CONG_VIEC_CON_LAI.md)
Đề tài: **Xây dựng AI Agent phân tích mã độc đánh cắp thông tin (Stealer) .NET/Python theo mô hình ReAct sử dụng SLM cục bộ** — Hướng 6.

## Mục tiêu hiện tại — hoàn thành toàn bộ đồ án

Cập nhật theo chỉ đạo mới nhất của người dùng ngày 27/11/2026: tiếp tục hoàn thiện toàn bộ đồ án theo tài liệu gốc và slide; buổi 4 chỉ là mốc tích hợp đã qua, không còn là đích bàn giao cuối. Mọi tiêu chí ANALYSIS, TRUST, YARA, GUARD, EFF, TRAIN và DELIVER phải có bằng chứng tương ứng trước khi coi dự án hoàn thành.

Người dùng đã cho phép chạy lại model khi cần. Có thể khởi động lab và Ollama để phân tích tĩnh, đo thực nghiệm, kiểm regression và đánh giá; tắt runtime sau từng đợt để trả RAM/VRAM. Chỉ xử lý mẫu trong VM cô lập, không thực thi mẫu. Yêu cầu tạm dừng trong giai đoạn tài liệu/phát hành trước đây không cấm những đợt kiểm chứng được cho phép mới này.

**Repo làm việc từ cập nhật mới nhất:** nhóm đã cấp quyền ghi vào `Gera-YCYC/PhanTichMaDoc-Stealer`. Từ đây push vào repo này, commit bằng tiếng Việt ngắn gọn, dùng danh tính Git của người dùng; không thêm tác giả/co-author/cộng tác viên cho công cụ. Lịch sử repo nhóm và bản source ban đầu được giữ; kho `duongthanhmong/PhanTichMaDoc_DoAn` chỉ là bản phát hành tạm trước đó. Sau chuyển repo tiếp tục phần kiểm chứng nhận định đang làm, không đổi mục tiêu thành chỉ xuất bản mã.

Phần mềm, dữ liệu đánh giá, các kết quả chưa đạt và hồ sơ huấn luyện phải minh bạch. Không thay mẫu khó bằng fixture rồi coi đạt; không đổi tiêu chí theo kết quả hiện có; không coi unit test hoặc script ứng viên là chứng cứ huấn luyện thật. Điều kiện cuối gồm báo cáo phân tích .NET/Python có luồng hành vi và chứng cứ, các metric đạt ngưỡng trên tập công bố, huấn luyện thực theo yêu cầu được chốt, tài liệu/slide/demo/log và hướng dẫn tái lập.

Người dùng làm rõ phạm vi bàn giao: cần sản phẩm đồ án và tài liệu kỹ thuật Markdown; không cần tên/MSSV, bìa báo cáo hoặc phân công cá nhân nếu không phục vụ xây dựng sản phẩm. Những thông tin hành chính và hoạt động vấn đáp của sinh viên không là điều kiện chặn hoàn thành sản phẩm. Slide gốc được giữ để truy vết; tài liệu hiện tại cần bao phủ thiết kế, triển khai, sử dụng, huấn luyện, đánh giá và giới hạn kỹ thuật.

Không giả nhận review của người thật hoặc xác nhận của GV. Ground truth phải có nguồn/chứng cứ độc lập với đầu ra agent; ghi rõ cách lập nhãn và mức kiểm chứng. Loại train GV muốn chưa được làm rõ, nhưng tiếp tục xây phần kỹ thuật và thực nghiệm có thể tái lập, không yêu cầu thông tin sinh viên để làm việc này.

## Lịch sử quyết định

Mã nguồn, môi trường phát triển, artifact và báo cáo đặt trên **ổ C**. Mô hình đã tải nằm tại `D:/Mountain-Market-Data/ollama-models`, hiện là `qwen2.5:1.5b`. Dùng mô hình này để phát triển theo chỉ định người dùng; **không đánh dấu đạt yêu cầu SLM tối thiểu 7B** của hướng 6. Không tự tải thêm model vào D.

**Cập nhật được người dùng cho phép ngày 27/11/2026:** nếu mô hình D không đáp ứng thì tải mô hình khác. Chọn `qwen2.5-coder:7b`, lưu mới tại `private/ollama-models` trên C do D chỉ còn khoảng 3 GB. Không xóa mô hình cũ; người dùng sẽ tự xử lý. Metadata và chạy thực tế quyết định đạt MODEL, không dựa vào tên tag.

**Lịch sử phân phối trước khi đổi repo đích:** người dùng yêu cầu push vào Gera-YCYC/PhanTichMaDoc-Stealer, đưa cả model/mẫu tải về cho nhóm, hướng dẫn từng bước và demo thật. Đã chọn Git cho source/docs, Release cùng repo cho 3 phần model + 5 mẫu public mã hóa + 2 manifest; không phân phối khóa cá nhân hay VM chứa khóa. Quyền Write đang chờ chủ repo cấp. Đây là ủy quyền publish cụ thể, thay cho quy tắc không tự publish khi chưa được yêu cầu. Tại thời điểm cập nhật cũ này, goal chưa được tạo lại; trạng thái mới nhất nằm ở mục cập nhật tiếp theo.

**Cập nhật giai đoạn phát hành trước khi tiếp tục toàn đồ án, 27/11/2026:** theo yêu cầu nhóm, repo đích chuyển sang https://github.com/duongthanhmong/PhanTichMaDoc_DoAn; source ở root, model/mẫu mã hóa ở Release. Goal đã được tạo lại, vẫn chưa hoàn thành toàn đồ án. Người dùng yêu cầu dừng runtime sau kiểm chứng, nên không tự bật lại Ollama/VM trong công việc tài liệu/publish. Không thêm tác giả/co-author AI hoặc cấp quyền collaborator cho công cụ. Yêu cầu training còn chờ GV làm rõ; xem training/DECISION_LOG.md.

| ID | Yêu cầu nguồn | Điều kiện đạt | Bằng chứng bắt buộc |
|---|---|---|---|
| M4 | Ảnh 10: buổi 4 | SLM thật điều khiển >=2 công cụ thật | Log model/dispatch/observation; backend thành công; VM isolation receipt |
| M6 | Ảnh 10: buổi 6 | >=3 mẫu có nhật ký | Manifest public có nguồn/hash và log từng mẫu theo cập nhật nhóm tự chọn mẫu |
| M8 | Ảnh 10: buổi 8 | Hoàn chỉnh và có bảng đánh giá | Từng nhận định đối chiếu ground truth |
| TOPIC | Ảnh 7 | Tham chiếu I .NET (5632 B), J PyInstaller (~8 MB); nhóm dùng public replacements | Hash/provenance mẫu public; kênh gửi/token/webhook; ILSpy/dnSpy và pyinstxtractor+pycdc |
| MODEL | Ảnh 7 | SLM >=7B cho hướng 6 | Metadata/digest và kết quả chạy; 1.5B chỉ phát triển |
| ANALYSIS | Ảnh 2,9 | P>=0.8, R>=0.7, F1>=0.75; nhắm F1>=0.8; verdict đúng 100% mẫu lab | Đáp án GV hoặc đáp án nhóm có nhãn riêng và bảng chấm |
| TRUST | Ảnh 2,9 | Bịa<=5%, grounding>=90%, ổn định 3 lần>=80% | Nhận định thô và đã kiểm chứng, citation, so sánh 3 run |
| TOOLS | Ảnh 9 | >=4 công cụ thật để nhắm xuất sắc | Version, exit code/status, input hash, output hash |
| YARA | Ảnh 2,9 | Agent sinh luật; TPR>=90%, FPR=0 | Luật, log compile, bộ positive/negative tách biệt, independent replay |
| GUARD | Ảnh 2,9 | Injection success=0%, >=10 file thử | Chạy cặp có/không injection; chưa đo thì null, không phải 0 |
| TRAIN | Yêu cầu bổ sung của GV qua nhóm | Có quy trình và thực nghiệm huấn luyện thật; loại train còn chờ làm rõ | Dataset/split/provenance, config, logs/loss/checkpoint, so sánh baseline; không gán nhãn người review giả |
| EFF | Ảnh 2 | Bước/tool/lỗi/thời gian/token/RAM/VRAM/chi phí | Telemetry thật, không đo được ghi null |
| DELIVER | Slide gốc và phạm vi người dùng cập nhật | Sản phẩm, source/log và Markdown kỹ thuật; giữ yêu cầu lớp để nhóm sử dụng | Cài/chạy/tái lập/thiết kế/train/đánh giá; không chặn vì thông tin sinh viên |

Quy tắc: mẫu và công cụ phân tích ở VM cô lập; SLM host chỉ nhận JSON đặc trưng/excerpt có giới hạn, không nhận binary. Không gửi mẫu lên cloud. Không chạy sample. Không shell tự do. Chỉ push/publish theo ủy quyền cụ thể của người dùng; repo đích đã được chỉ định ở trên. Mock, fixture lành, unit test, model smoke và nghiệm thu môn học là các loại bằng chứng riêng.

**Cập nhật người dùng ngày 27/11/2026:** giảng viên không cấp I/J; nhóm tự chọn mẫu công khai. Thay điều kiện chờ mẫu GV bằng bộ mẫu public có nguồn, hash, định dạng kiểm chứng và ground truth do nhóm đối chiếu độc lập. Không gọi mẫu thay thế là đúng I/J gốc, không ép kích thước giống slide. Nguồn gốc slide được giữ nguyên ở trên để truy vết. `teacher_dataset_verified=false` vẫn đúng vì đây không phải bộ GV cấp; nghiệm thu cần bao phủ tập mẫu nhóm đã công bố.

Mọi gate thiếu bằng chứng giữ trạng thái pending. Regex guard và quote matching không tự chứng minh nhận định đúng ngữ nghĩa hoặc miễn nhiễm injection.
