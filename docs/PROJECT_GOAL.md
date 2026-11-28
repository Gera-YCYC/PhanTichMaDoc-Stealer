# Goal và điều kiện nghiệm thu

## Mục tiêu sản phẩm cập nhật ngày 28/11/2026

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
