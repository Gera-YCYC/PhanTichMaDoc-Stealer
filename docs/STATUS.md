# Trạng thái sản phẩm ngày 28/11/2026

**Chưa hoàn thành toàn bộ đồ án.** Mục tiêu là sản phẩm phân tích stealer .NET/Python theo toàn bộ slide/đề xuất, không còn dừng ở buổi 4. Tài liệu bàn giao là Markdown kỹ thuật; thông tin sinh viên và bìa báo cáo không là điều kiện chặn.

## Cập nhật hiện tại

Hai mẫu .NET đã được truy vấn bổ sung trong VM theo hai cách, cùng bốn lần tìm mỗi mẫu mỗi cách. Danh sách cố định lấy đủ dòng cho **6/20** mục còn thiếu ở tầng truy xuất, Qwen chọn theo tên đã quan sát được **3/20**. Nhánh Qwen tốt hơn trên Mercurial và kém hơn trên Gomorrah. Phần Đánh giá có bảng riêng để xem thời gian và các mục tìm thấy. [Phương pháp và kết quả cụ thể](CHAM_BA_MAU_WEB.md#tìm-thêm-chứng-cứ-trong-vm-trên-hai-mẫu-net)

Đã kiểm tra trực tiếp chức năng đọc lại câu bị loại trên Mercurial và Gomorrah. Cùng được Qwen giữ nhưng chỉ câu Mercurial có đủ chứng cứ. Phần Đánh giá công bố cả nhãn đối chiếu, số lần gọi và thời gian của hai cách chọn dòng trên 13 câu. [Cách mở hai ví dụ và tái lập](DOC_LAI_NHAN_DINH.md)

Nhóm đã chạy lại demo web thật trên mẫu Python trong 495,58 giây, kiểm tra hai câu hỏi điều tra, kết quả YARA và tắt lab. Cả 30 câu trước lọc trùng với lượt Python đầu tiên, bộ duyệt thay hai quyết định. Lượt lặp đạt F1 70,18% trên hồ sơ 36 mục. [Mã lượt, tọa độ, số liệu và cách trình diễn](WEB_DIEU_TRA.md)

Trên bản đồ web, mỗi liên kết có lịch sử các truy vấn thực sự được ghi cho nó. Bấm vào trích dẫn để xem đoạn mã có đánh số dòng, các giá trị chuỗi đã che và hash nguồn. Trang Đánh giá đã có bảng đối chiếu cho sáu đoạn bổ sung và phép duyệt có/không có tài liệu Windows CNG. Các phép thử bổ sung chưa cải thiện điểm cuối. [Chi tiết và lệnh kiểm lại](THU_CHON_DOAN_CHUNG_CU.md)

**Bản web hiện hành đạt mốc ba mẫu có nhật ký của buổi 6.** PythonStealer, Gomorrah và Mercurial đã được phân tích tĩnh trong VM, dùng cùng mã agent và Qwen3 8B trên Windows. Tính mỗi mẫu một lần, kết quả sau tự duyệt là precision 89,74%, recall 36,08%, F1 51,47%, F1 riêng IOC và ATT&CK 42,86%, verdict đúng 0/3. Đã chấm nguồn cho cả câu giữ lại và câu bị loại. [Bảng điểm, giới hạn và cách trình diễn](CHAM_BA_MAU_WEB.md)

Đã chấm toàn bộ ba báo cáo web trên cùng mẫu Python phát triển, gồm 99 lượt nhận định trước lọc. Sau lọc, từng báo cáo phủ 19, 20 và 19 trên 36 mục. F1 lần lượt 69,09%, 70,18% và 65,52%. Trên web có thể xem cả câu sai được giữ, câu đúng bị loại và vị trí các mục bị bỏ sót trong quá trình điều tra. [Bảng chấm, bằng chứng và lệnh tái lập](CHAM_BAO_CAO_WEB.md)

Giao diện web đã gọi agent, Ollama Qwen3 8B và VM cô lập trên máy lab. Lượt Python có 3/7 quan hệ tĩnh đủ bằng chứng. Khi hỏi về hai quan hệ khác nhau, một câu dùng lại 11 trích dẫn và một câu cần truy vấn VM bổ sung. Cả hai được ghi thành nhật ký riêng. Trên mười vị trí có đáp án phát triển, quy trình cố định tìm được một vị trí, quy trình chọn truy vấn theo quan sát tìm được ba vị trí với cùng tám lần tìm trong VM. Quy trình thứ hai dùng thêm tám lượt gọi model. [Demo, thời gian và số liệu đối chứng](WEB_DIEU_TRA.md)

Bảng chấm bốn mẫu v11 là mốc so sánh chất lượng toàn báo cáo. Sau lọc, precision đạt 81,67%, recall 47,12%, F1 59,76% trên 104 mục, verdict đạt 0/4 theo cách chấm lành/độc. Chưa có bảng chấm độc lập đầy đủ cho phiên bản web. [Phạm vi và kết quả chấm](DEMO_COVERAGE.md)

Ba lượt web trên Python cho cùng verdict `suspicious` và cùng ba liên kết có bằng chứng. Độ ổn định nhận định đạt 27/38 (71,05%), dưới mục tiêu 80%. [Nhật ký và cách tính](WEB_DIEU_TRA.md#độ-ổn-định-của-ba-lượt-python)

### Các phép đo trước khi có giao diện web

Bản v13 hoàn tất phân tích Mercurial bằng Qwen3 8B, kèm lần quét YARA thực tế và phép đo bộ nhớ. Câu T1539 có đủ hai đoạn mã nối liên tục. YARA khớp `LabCorpus_05`. Sau lọc, F1 riêng IOC + ATT&CK là 40% trên mẫu này, F1 trên toàn bộ 21 mục là 43,75%. Máy đã tắt VM và Ollama sau đợt đo. [Demo và hai bảng chấm v12/v13](DEMO_COVERAGE.md#demo-mercurial-với-chứng-cứ-ioc-và-attck) · [Trạng thái máy sau demo](../deliverables/real-demo-evidence/runtime-stopped-after-techniques-v13.json).

Lượt Mercurial dùng `techniques-8b` hoàn tất sau 493,4 giây. VM tìm được cấu hình webhook ở dòng 37. Qwen gán T1539 nhưng thiếu trích dẫn nối bản sao dữ liệu với nguồn. Trong 12 câu giữ lại có 9 câu được chứng cứ của chính câu đó xác nhận. F1 trên 21 mục sau tự duyệt đạt 62,86%. [Lệnh demo và biên bản chấm](DEMO_COVERAGE.md#demo-mercurial-với-chứng-cứ-ioc-và-attck).

Ba lượt `guided-8b` trên cùng AgentTesla có 4/28 nhận định lặp nguyên nội dung (14,29%) và cùng verdict `inconclusive`. Trong phép so có và không dùng trọng số ranker, hai nhánh đều giữ 12 câu, cùng phủ 2/7 mục. [Ba lần chạy và phương pháp so](../deliverables/real-demo-evidence/agenttesla-guided-stability.json) · [Quá trình train và tác động đo được](../training/RANKER_EXPERIMENT.md).

Đợt `coverage-8b` đã chạy trên bốn mẫu thật trong VM. PythonStealer, Gomorrah và Mercurial có báo cáo chứa nhận định, đủ mốc buổi 6. AgentTesla có 14 truy vấn rỗng và được tính vào bốn lượt đã thử. F1 gộp IOC + ATT&CK trên ba mẫu có đáp án cho hai loại này là 16,67%. Verdict chính xác trên bốn mẫu độc là 0/4. [Các mẫu số và lý do chấm](DEMO_COVERAGE.md) · [Video nhật ký thật](../deliverables/Demo_phan_tich_tinh.mp4).

Lượt đầu-cuối Python với Qwen3 8B và báo cáo v11 đã hoàn tất trong 588,6 giây. Có 36/39 câu đủ chứng cứ, Recall 61,11% trên 36 mục tham chiếu và verdict `suspicious`. Nhóm đã lập thêm 40 đơn vị tham chiếu .NET từ kết quả ILSpy của Gomorrah. [Số đo và hướng dẫn tái lập](DEMO_COVERAGE.md).

### Các lượt trước với báo cáo v9 và v10

Parser v4 nhận diện thêm copy/read/write/fetchall/DPAPI/MIME/TLS; kiểm riêng source thật có39 fact Python và10 .NET, kiểm HTTP dùng phiên mới đạt. **Đó là kiểm công cụ, không là accuracy của SLM.** Run ReAct v9 mới mất495,9s,4 backend thành công,18 câu raw có13 đúng/5 thiếu căn cứ; sau lọc11/14 đúng. Có hostname SMTP thật trong source nhưng không có ATT&CK. [Nguồn và phân tích lỗi](OPERATIONS_CONTEXT_V9.md).

Đã đo cả Recall/F1 cho báo cáo đầy đủ trong phạm vi34 đơn vị development:22 đơn vị prediction,17 đúng/5 thiếu căn cứ; **P 77,27%, R 50%, F1 60,71%; sau lọc F1 52%**. Không dùng Precision theo18 câu ghép với Recall theo34 đơn vị. Profile mới giữ29 đơn vị cũ, thêm5 đơn vị source download/autofill sau lượt chạy; không giả test mù hoặc nhãn GV.

Bản v10 chặn IOC kiểu biểu thức bằng schema lựa chọn literal và tách tên API tham chiếu khỏi cú pháp gọi thật. **318 kiểm thử Windows đạt.** Lượt v10 từ đầu bị guard RAM dừng trước báo cáo (189,6s,255.528.960B trống), nên chưa có kiểm chứng đầu-cuối hoàn tất cho v10. Không hạ ngưỡng RAM và không gán điểm chất lượng cho lượt dở. Giữ nhánh candidate; model/Release mặc định vẫn7B. Các số đo report v10 trên chứng cứ đã thu phải được ghi riêng với lượt chạy VM mới.

Phép thử report v10 thật trên đúng các đoạn source v9 đã hoàn tất:12/12 câu raw đúng,15/34 đơn vị nguồn được phủ (P 100%, R 44,12%, F1 61,22%). Reviewer loại nhầm2 câu đúng; sau lọc F1 48,89%, không có ATT&CK, verdict vẫn suspicious. R giảm so v9, nên không coi hết lỗi IOC là đạt toàn phân tích. **Đây là report-stage trên chứng cứ thật đã thu, không thay lượt đầu-cuối bị dừng.** Model và VM đã tắt; [receipt](../deliverables/real-demo-evidence/runtime-stopped-after-cards-v10.json) ghi GPU0MiB tại lúc kiểm.

Các phần chưa đóng: nối thu thập–xử lý–gửi và verdict, Recall/F1 toàn tập .NET/Python, >=3 mẫu trên bản chốt, stability3lượt, >=10 cặp injection đủ exposure, so trước/sau train trong agent và tái lập bản chốt. YARA đã đạt trên corpus hữu hạn ở mục dưới; không ghép điểm khác phiên bản thành nghiệm thu.

### Báo cáo theo thao tác: đã có số đo phần đúng và phần bỏ sót

[Thử nghiệm riêng phần báo cáo](ATOMIC_REPORT_STAGE.md) đã chạy model thật trên bằng chứng VM của mẫu thật: Python8B6/6 câu hẹp đúng, .NET8B10/10, Python7B4/4 nhưng loại nhầm2 thao tác đúng. Tập đáp án Python được tách thành29 đơn vị gồm26 hành vi,1 IOC,2 ATT&CK; bộ chấm mới dùng cùng đơn vị cho P/R/F1 và giữ cả raw/rejected. Python8B chỉ bao phủ6/29 (R20,69%, F134,29%);7B4/29 (R13,79%, F124,24%). Đây là development/source audit, không có người thật/GV duyệt. .NET chưa có normalized reference, R/F1null.

**Không thay demo chính bằng catalog API hẹp.** Phần mới chỉ có trong runner thử nghiệm, chưa xác lập IOC/ATT&CK/luồng dữ liệu/verdict. Snapshot23file host được giữ để tái lập; không gán số đo này cho các sửa guard sau đó. Model đã dừng: [receipt](../deliverables/real-demo-evidence/runtime-stopped-after-atomic-stage.json). Ưu tiên tiếp theo là mở rộng bằng chứng và gắn các thao tác vào đầy đủ chuỗi phân tích, không thu hẹp đề tài để tăng Precision.

### YARA thật đã đo trên 5 mẫu độc và 39 file sạch

Đã tích hợp profile corpus thật, chọn chuỗi có offset trong byte gốc, đọc TOC PyInstaller và vòng SLM sinh/kiểm luật tối đa bốn lượt. Đã tìm ra báo nhầm yt-dlp ở luật ban đầu (**1/38**), giữ kết quả âm rồi sửa; không lấy số đo fixture để nghiệm thu.

Hai lượt cuối trên cùng source/corpus: **Qwen7B 5/5 positive, 0/39 negative báo nhầm trong 42,5s; Qwen3 8B 5/5 và 0/39 trong 73,0s.** Mỗi lượt có 5 model call, 14 tool call không tính đọc trang, replay độc lập khớp. [Toàn bộ cách đo, log và hạn chế](YARA_REAL_CORPUS.md). **236 kiểm thử phần mềm đạt trên Windows** ở bản này; không phải 236 mẫu độc.

Ngưỡng YARA đạt trên corpus công bố, gồm các mẫu development/đã xem; không chứng minh khả năng phát hiện mọi biến thể mới. Hai luật Python phụ thuộc tên entry bản build; AgentTesla còn phụ thuộc tên executable. Corpus có 37 tiện ích Microsoft và hai ứng dụng PyInstaller chính thức. Các gate ANALYSIS/TRUST/GUARD và đánh giá train vẫn chưa đạt; không dùng kết quả YARA thay điểm của báo cáo hành vi.

### Báo cáo v8, truy vấn theo hàm và provenance đầy đủ

**Chất lượng vẫn chưa đạt.** [Thiết kế v8](OPERATIONS_CONTEXT_V8.md) gồm AES-GCM fact hẹp, chọn đoạn đầy đủ theo thao tác, đưa cùng source/fact vào generator và reviewer, truy vấn literal từ tên hàm đã quan sát và log nguyên messages/schema. **223 kiểm thử phần mềm đạt trên Windows.** Đây là kiểm hợp đồng, không phải 223 mẫu độc.

| Lượt thật | Kết quả | Diễn giải |
|---|---|---|
| Qwen3 8B `20261127T203557_3580d286` | Ngắt do RAM còn 199.147.520 byte, 4 tool thành công | Chưa tạo report; không có điểm chất lượng |
| 7B, query tự do `20261127T204500_5a3210fc` | 7 tool, 1 query lặp, 2 JSON lỗi | Thử nghiệm thất bại được giữ; bản hiện tại dùng enum mở rộng theo source |
| 7B, query từ source `20261127T210746_9922cc4e` | 162,2 s, 4 tool, 27 model call; 0 câu trên 9 card | Không tính đạt. Log cũ ghi completed_needs_review; đã sửa code để lần sau báo cáo rỗng là incomplete, không viết lại log lịch sử |
| 8B, query từ source `20261127T211223_9602dfdd` | 484,7 s, 4 tool, 36 model call; verdict suspicious | 8/11 câu đủ căn cứ, 3 thiếu căn cứ; tự duyệt còn 4/6 đúng |
| 8B, .NET `20261127T212209_478cc179` | 503,5 s, 2 tool, 49 model call; verdict suspicious | 14/20 câu đúng, 1 sai, 5 thiếu căn cứ; sau lọc 14/19 đúng |

Lượt Python cuối có Precision/grounding **72,73%**, hallucination **27,27%**; sau lọc lần lượt **66,67%** và **33,33%**. Recall/F1 vẫn `null` vì chưa chuẩn hóa đủ đơn vị đáp án. Bốn câu đúng bị cùng model loại, hai câu thiếu căn cứ được giữ. [Audit đủ 11 câu](../eval/adjudications/python2024-operations-v8-full-audit.json), [score](../deliverables/real-demo-evidence/python2024-operations-v8-claim-score.json), [receipt chạy](../deliverables/real-demo-evidence/operations-v8-source-query-8b-python-run.json). Nhãn do source audit tự động, chưa có người thật/GV duyệt.

Audit privacy kiểm đủ 36 messages và 36 schema của lượt Python 8B; ba literal detector đã nhận diện không xuất hiện trong request/schema/response. [Receipt](../deliverables/real-demo-evidence/model-projection-v8-source-query-8b-python.json). Chỉ kết luận trong phạm vi detector, không bảo đảm mọi bí mật đều được tìm thấy.

Lịch sử v8 đã nhập và khóa **8 file sạch thật có chữ ký Microsoft** cùng 5 mẫu độc development trong manifest riêng. Sau đó bộ YARA mở rộng lên39negative và được đo như phần cập nhật phía trên. [Corpus và cách tái lập](CLEAN_CORPUS.md). Chưa có positive holdout; không dùng receipt nhập file thay kết quả quét.

Nhánh .NET đã phân biệt đúng file upload với response ASCII trong các câu C1–C8, nhưng còn suy tác dụng `Decrypt` khi thiếu thân hàm, nhầm tên biến với tên field/filename, và suy lời gọi từ khai báo P/Invoke. [Audit đủ 20 câu](../eval/adjudications/gomorrah-operations-v8-full-audit.json), [score](../deliverables/real-demo-evidence/gomorrah-operations-v8-claim-score.json), [receipt](../deliverables/real-demo-evidence/operations-v8-source-query-8b-dotnet-run.json). Precision 70%, hallucination 25%. Riêng lượt .NET dùng 2 công cụ; hợp hai lượt có 5 công cụ thật khác nhau, đáp ứng phần số lượng >=4 của tiêu chí kỹ thuật. Slide không yêu cầu mỗi mẫu gọi đủ 4; phần luật YARA trong cùng tiêu chí còn mở. Hai lượt 8B dùng cùng manifest 44 file core, hash `11c3e88b9f4d9e280548a022f4a89a771cabb5996dc46924981b200856e8fea6`.

Nhật ký .NET có đủ 49 messages/schema nhưng detector không tìm thấy literal riêng tư đủ điều kiện trong các đoạn đã truy hồi. [Audit `/3`](../deliverables/real-demo-evidence/model-projection-v8-source-query-8b-dotnet.json) để gate privacy `null`, không biến tập rỗng thành pass. Kiểm thử thứ 223 xác nhận điều này; các audit cũ vẫn giữ riêng theo revision.

Đã dừng runtime sau đợt đo: PID Ollama 9148 không còn, cổng 11435 không lắng nghe, VMware báo 0 VM chạy, GPU quan sát 0/6144 MiB. Model và đĩa VM giữ nguyên. [Receipt dừng](../deliverables/real-demo-evidence/runtime-stopped-after-operations-v8.json). Lần chạy sau dùng Start-Lab/sync/verify theo TEAM_SETUP; việc tắt runtime không đánh dấu mục tiêu đồ án hoàn thành.

Các mục dưới giữ nguyên số đo lịch sử theo revision. Không lấy kết quả tốt nhất ở các revision khác nhau ghép thành một lần nghiệm thu.

### Lịch sử v7: truy xuất nhiều hàm và che literal trước mô hình

- Đã sửa lỗi v2 dùng cả hai slot cho cùng một hàm khi truy vấn trả hai anchor. `tree-sitter-context/3` chia ngân sách theo hàm chứa hit; `evidence-cards/7` giữ hai caller khác nhau của cùng helper. [Kiểm HTTP thật](../deliverables/real-demo-evidence/context-v3-projection-http-check.json) tái chạy công cụ VM và xác minh cả hai nhánh cùng có helper; [giải thích](SYNTAX_CONTEXT.md).
- Run ReAct mới **`20261127T201007_3f8805e5`**, Python2024 public + Qwen3 8B + VM thật: **433,9208 giây, 4 tool thành công, 17 tool call, 38 model request**, 1 lỗi pycdc; 7 card, 12 câu thô/11 được giữ, verdict **suspicious**. Có 6 typed operations; chưa dùng chúng chấm tự động câu SLM. [Receipt](../deliverables/real-demo-evidence/context-v3-projection-python-run.json).
- [Audit đủ 12 câu](../eval/adjudications/python2024-context-v3-projection-full-audit.json): **9 đúng, 0 sai đối chiếu, 3 thiếu căn cứ**. Precision/grounding **75%**, hallucination theo định nghĩa thiếu căn cứ **25%**. Sau lọc chỉ 8/11 đúng (**72,73%**) vì reviewer loại nhầm C2. [Score](../deliverables/real-demo-evidence/python2024-context-v3-projection-claim-score.json). Chưa đạt các ngưỡng 80%/90%/<=5%; Recall/F1 vẫn null. Đây là source audit phát triển, chưa có người thật/GV phê duyệt; không suy cải thiện toàn corpus từ một lượt.
- `model-evidence-projection/1` che literal nhận diện được trước controller/generator/reviewer, giữ raw riêng và đánh dấu quote là bản chiếu tại tọa độ gốc. [Audit mới](../deliverables/real-demo-evidence/model-projection-v7-live-audit.json) nhận diện 3 literal: **0/38 request-evidence và 0/38 response** còn các giá trị này; 17 observation được tái tạo bản chiếu từ raw. [Baseline v5](../deliverables/real-demo-evidence/model-projection-v5-baseline-audit.json) lần lượt có 11/41 và 2/41. Đây không phải recall của detector. Chỉ 20/38 request có full message, 18 controller request có evidence/hash; gate full-request giữ null. [Thiết kế và giới hạn](MODEL_INPUT_PROJECTION.md).
- **195 test phần mềm đạt trên Windows**, gồm chia ngân sách nhiều hàm, hai caller dùng chung helper, projection, hash/tamper và input card. Không phải 195 mẫu malware. CI của commit mới phải được kiểm riêng sau push.
- Đã dừng đúng Ollama dự án và VM. [Receipt sau đợt](../deliverables/real-demo-evidence/runtime-stopped-after-context-v3-projection.json) xác nhận PID/cổng không còn, VM chạy bằng 0; GPU toàn máy 0 MiB tại lúc kiểm. Trọng số/đĩa VM được giữ.

Ưu tiên kế tiếp: sửa chọn card khiến helper hostname chiếm slot của hàm gửi email đầy đủ; đưa typed operations vào nhận định có cấu trúc để hạn chế suy tác dụng từ tên hàm; sửa reviewer loại nhầm giải mã; bổ sung full-request/schema provenance. Sau đó kiểm lại cả .NET/Python, IOC/ATT&CK/YARA, bộ sạch/holdout, stability và injection. Model mặc định/Release vẫn giữ Qwen2.5 Coder 7B; không đổi từ phép đo đơn lẻ này.

### Lịch sử v5/v6 để đối chiếu

- **Run sau bổ sung dependency context** `20261127T193524_b2342ecf` đã hoàn tất bằng Qwen3 8B + công cụ VM thật: 512,6999 giây, 4 tool thành công/17 call, 41 model request, 1 lỗi pycdc, verdict suspicious. [Receipt](../deliverables/real-demo-evidence/dependency-context-v2-python-run.json). Có 5 typed operations phiên bản 2 trong báo cáo. Helper giải mã đã có trong citation C2, nhưng reviewer vẫn loại nhầm.
- Đối chiếu đủ 14 câu của run này: **9 đúng, 3 sai, 2 thiếu căn cứ**; Precision/grounding 64,29%, hallucination 14,29%. Sau lọc 8/12 câu đúng (66,67%). [Audit đầy đủ](../eval/adjudications/python2024-dependency-context-v2-full-audit.json), [score](../deliverables/real-demo-evidence/python2024-dependency-context-v2-claim-score.json). Chưa đạt Precision 80%, grounding 90% hoặc hallucination <=5%; không có xác nhận của GV/người thật.
- Đã định nghĩa và kiểm source cho **13 đơn vị hành vi phát triển**. Report thô phủ 7/13, sau lọc 6/13; đây là coverage của subset, không phải Recall toàn corpus. [Phương pháp, bảng ghép và giới hạn](../eval/reference_units/README.md). F1 vẫn null vì độ chi tiết câu và đơn vị tham chiếu chưa đồng nhất.
- Cải tiến ở host: loại link bị một card đầy đủ bao trọn; hit trong khoảng thứ hai/ba cũng được gắn vào card sẵn có. Phương pháp mới `evidence-cards/6`; **183 test phần mềm đạt trên Windows**. Replay với SLM thật từ evidence đã lưu hoàn tất 207,046 giây, 20 request, 12 câu thô/9 được giữ; [receipt](../deliverables/real-demo-evidence/report-selection-v6-replay.json). Không phải demo ReAct/tool mới.
- Source audit replay v6: 8/12 câu đúng (66,67%), 1 sai, 3 thiếu căn cứ; [score](../deliverables/real-demo-evidence/python2024-cards-v6-replay-claim-score.json). Còn lỗi helper bị thiếu và nhầm bộ đếm; raw prose lặp hai literal credential đã có trong source. Bản xem local che được hai literal đã nhận diện, nhưng raw vẫn private và không được duyệt công bố. Không đổi baseline/Release từ phép thử này.
- Đã dừng Ollama sau replay; VM vẫn tắt trong phép đo này. [Receipt cuối đợt](../deliverables/real-demo-evidence/runtime-stopped-after-cards-v6-replay.json) kiểm PID, cổng, VM và bộ nhớ tại thời điểm đó. Model/đĩa VM giữ nguyên.

Các mốc v5 trước bổ sung dependency được giữ ở dưới để đối chiếu.

- **168 kiểm thử phần mềm đạt trên Windows** ở bản thêm dữ kiện API và kiểm binding. Bộ test dùng source vô hại, không phải 168 mẫu malware. Bản CI của commit công khai trước đó có 137 test; bản mới phải được CI xác nhận riêng.
- Run thực `20261127T184945_91217ab1` dùng Qwen3 8B và `evidence-cards/5`: 447,8409 giây, 4 tool thành công, 17 tool call/43 model call, 1 lỗi pycdc, verdict **suspicious**. Có 6 dữ kiện API từ VM đi vào báo cáo (2 mở DB, 2 SELECT, 1 SMTP, 1 archive); chúng được trình bày riêng, chưa dùng để chấm đúng/sai cho câu SLM. [Receipt run v5](../deliverables/real-demo-evidence/cards-v5-python-run.json).
- Đã đối chiếu đủ 16 câu thô v5 với citation thực: **10 đúng, 1 sai, 5 thiếu căn cứ; Precision 62,5%, hallucination 31,25%, grounding 62,5%**. Reviewer giữ 15 câu, trong đó 9 đúng (60%), loại nhầm một câu đúng. Recall/F1 chưa có tập đơn vị reference đầy đủ nên để null. Chưa đạt các ngưỡng cuối môn; đây là source audit phát triển, chưa có người thật/GV phê duyệt. [Nhãn đủ 16 câu](../eval/adjudications/python2024-qwen3-cards-v5-full-audit.json), [bảng tính](../deliverables/real-demo-evidence/python2024-cards-v5-claim-audit-score.json).
- Thử ghi chú API và reviewer suy luận đã được lưu cả kết quả âm; [phân tích](API_REFERENCE.md) phân biệt replay ba card, reviewer 19 câu và smoke suy luận ba câu. Không đổi baseline/Release; không gọi prompt/reference là training.
- Bộ parser [typed operations](TYPED_OPERATIONS.md) dùng AST/tree-sitter trong VM. Sau run v5 đã sửa ý nghĩa return của SQLite thành cursor, bổ sung citation `using` C#, chặn thêm namespace sai/ref mutation/reimport/monkeypatch. Backend hiện là `static-operation-facts/2`; run v5 vẫn dùng `/1`, không thay bằng chứng lịch sử. [Backend v2 trên source thật](../deliverables/real-demo-evidence/typed-operations-v2-real-source-check.json) nhận 10 thao tác .NET và 12 Python; [6 lượt HTTP tìm kiếm qua VM/guard](../deliverables/real-demo-evidence/typed-operations-v2-delivery-check.json) đạt. Đây là kiểm tích hợp công cụ thật, không phải lượt SLM mới hay điểm chất lượng.
- Truy vấn .NET rộng `UploadFile` có thể ưu tiên `LateGet` mà parser chưa hỗ trợ. Fact rỗng trong trường hợp này là giới hạn nhận dạng, không phải kết luận lành. Tài liệu giữ hạn chế đó; kiểm thêm dạng trực tiếp `.UploadFile(` và `Encoding.ASCII.GetString` không được dùng để thay số đo ReAct.
- Đã tắt server Ollama và VM dự án sau đợt đo v5/v2 để trả RAM/VRAM. Trọng số và đĩa VM giữ nguyên; [receipt sau dừng](../deliverables/real-demo-evidence/runtime-stopped-after-cards-v5.json) ghi trạng thái tại thời điểm kiểm.

Các dòng dưới là kết quả v4 đã công bố, không phải trạng thái kiểm thử mới nhất.

- **137 kiểm thử phần mềm đạt trên Windows** sau bổ sung ngữ cảnh cú pháp và sửa che literal trong báo cáo. 131 ca đã đạt trước hai run v4; 6 ca mới kiểm redaction. Đây không phải accuracy trên 137 malware.
- Hai run mới dùng Qwen3 8B, cùng source phân tích `evidence-cards/4` đã khóa trước chạy: Python `20261127T175019_6cbdf3e9` hoàn tất 511,506 giây, 4 công cụ/17 tool call/43 model request; Gomorrah `20261127T180215_b3a8ccf4` hoàn tất 563,8431 giây, 3 công cụ/17 tool call/48 model request. Cả hai verdict **suspicious**. [Receipt hai nền tảng](../deliverables/real-demo-evidence/cards-v4-platform-runs.json) đã kiểm hash chain và ghép request/response.
- [Ngữ cảnh hàm](SYNTAX_CONTEXT.md) được thêm bằng tree-sitter trong VM; source/excerpt vẫn được giữ nguyên. Đây là quan hệ cú pháp hỗ trợ tìm chứng cứ, chưa là bằng chứng luồng dữ liệu đầy đủ. Parser không được tính thêm distinct analysis tool.
- Python v4: 16 câu thô, source audit chấm 8 đúng/3 sai/5 thiếu căn cứ; Precision 50%, hallucination 31,25%, grounding 50%. Sau tự duyệt còn 14 câu, chỉ 6 đúng (42,86%), hai câu đúng bị loại. .NET v4: 19 câu thô, 7 đúng/4 sai/8 thiếu căn cứ, Precision 36,84%; sau lọc chỉ 2/9 câu đúng, năm câu đúng bị loại. **Chưa đạt chất lượng; Recall/F1 để null.** Đây là nhãn từ source audit, chưa có người thật/GV phê duyệt. [Đối chiếu](CLAIM_AUDIT.md).
- Phát hiện credential hardcode bị model nhắc lại trong prose. Bản sửa redaction áp dụng sau hai run, không đổi log/source đã dùng để phân tích. Kiểm lại bản xem cục bộ trên báo cáo lưu sẵn: hai literal được nhận diện trong Python đều bị che ở cả source và prose; không còn literal đã nhận diện trong bản render. Đây không phải một lượt inference mới hoặc chứng nhận đã phát hiện mọi bí mật. [Receipt](../deliverables/real-demo-evidence/report-redaction-v1-check.json); [thiết kế và giới hạn](REPORT_REDACTION.md).
- Đã tắt đúng server Ollama và VM dự án sau hai lượt: không còn PID/cổng/runner của dự án, VM không chạy; GPU toàn máy quan sát 0 MiB tại thời điểm kiểm. [Receipt](../deliverables/real-demo-evidence/runtime-stopped-after-cards-v4.json). Trọng số/đĩa VM giữ nguyên. Lần chạy tiếp cần sync source mới vì redaction được sửa sau đợt đo.

Các mục ngay dưới là mốc trước v4, giữ riêng để so sánh và không viết đè số liệu lịch sử.

- Repo chính đã chuyển sang **Gera-YCYC/PhanTichMaDoc-Stealer**; lịch sử nhóm và 27 tệp source gốc giữ nguyên. Release nhóm đủ 10 asset, đã kiểm hash/tải thử. [Biên bản công bố](PUBLISH_STATUS.md).
- **119 kiểm thử phần mềm đạt trên Windows** ở bản bổ sung giữ anchor, chặn import-only, kiểm căn cứ verdict và chấm đủ câu thô. Không phải accuracy trên 119 mẫu mã độc.
- Nhánh báo cáo hiện có `report_method=evidence-cards/3`, vẫn dùng cờ cấu hình `evidence-cards-v1` để tương thích. Kết luận malicious cần tham chiếu đủ thu dữ liệu nhạy cảm, gửi dữ liệu và liên kết giữa hai bước; các vai trò do SLM gán vẫn cần kiểm nghĩa.
- Run Python thật `20261127T171819_406f8937` hoàn tất 458,6038 giây, 4 công cụ thành công/17 tool call/35 model request. Có 10 câu thô, giữ 7/loại 3; verdict **suspicious**. RAM khả dụng nhỏ nhất đo giữa request 534.048.768 byte; pycdc vẫn lỗi, decoder chỉ phục hồi candidate source. [Receipt](../deliverables/real-demo-evidence/cards-v3-python-run.json).
- Đã đối chiếu đủ câu của ba lượt v1/v2/v3, có kiểm hash và giữ mẫu số gồm các câu bị loại. V3 có 7 câu đúng, 1 câu sai cách mô tả truy vấn/giải mã, 2 câu thiếu dẫn chứng theo source audit; Precision 70%, chưa đạt ngưỡng 80%. Recall/F1 chưa có đơn vị đối chiếu đầy đủ nên để null. [Phân tích và giới hạn](CLAIM_AUDIT.md).
- Run Gomorrah .NET thật `20261127T172625_ba003503` dùng cùng source/model/config, hoàn tất 467,2824 giây với pefile, ILSpy và DIE; 17 tool call, 49 model request, không lỗi tool/schema. Có 20 câu thô, reviewer giữ 16/loại 4, verdict **suspicious**. Đây chưa phải 16 câu được đối chiếu độc lập. [Receipt hai nền tảng](../deliverables/real-demo-evidence/cards-v3-platform-runs.json).
- Đã dừng server Ollama/runner của dự án và tắt VM sau hai lượt; [receipt cuối đợt](../deliverables/real-demo-evidence/runtime-stopped-after-cards-v3.json) ghi kiểm PID, cổng và VM. Weight và đĩa VM được giữ nguyên.

Các mục bên dưới giữ kết quả lịch sử tại từng revision. Kết quả mới không thay đổi số liệu cũ hoặc biến model candidate thành mặc định. Mục tiêu toàn đồ án vẫn chưa hoàn thành.

## Lịch sử báo cáo đoạn và tài nguyên ngày 27/11

- **94 kiểm thử phần mềm đạt trên Windows** ở bản thêm khoảng dẫn chứng, báo cáo đoạn và tách provenance decoder. Không phải accuracy trên 94 malware.
- Đã triển khai nhánh thử `evidence-cards-v1`: SLM chọn `finalize`, viết từng đoạn đã truy xuất, kiểm từng claim, tổng hợp verdict từ tập được giữ; log lưu cả câu bị loại. Khoảng citation được đối chiếu chính xác từng dòng/hash mẫu. [Thiết kế và cách chạy](EVIDENCE_CARDS.md).
- Đã xác định cache prompt của runtime tăng đến **2.679,6 MiB** trong log trước sửa (trần 8.192 MiB). `Start-LocalModel.ps1` giới hạn riêng cache dự án ở **256 MiB**; log sau sửa xác nhận trần này, giá trị lớn nhất quan sát 252,769 MiB. Đây là số đo cache ở các dòng log, không phải peak RAM toàn hệ thống. [Receipt](../deliverables/real-demo-evidence/prompt-cache-bound.json).
- Hai run Qwen2.5 Coder 7B hoàn tất trên Python/Gomorrah sau giới hạn cache, nhưng cả hai trả báo cáo rỗng. Giữ kết quả âm; không tính rỗng là 0% hallucination. [Bốn run gồm cả lỗi RAM](../deliverables/real-demo-evidence/cards-qwen25-runs.json).
- **Run thật Qwen3 8B `20261127T164056_2bc4e796`** trên Python: 4 tool thành công, 17 tool calls, 37 model calls, 376,1841 s; 12 claim thô, reviewer giữ 9/loại 3; verdict malicious. RAM khả dụng nhỏ nhất giữa request 815.947.776 B; VRAM cuối run theo API 4.206.582.824 B. Đây là một nhãn khớp trên một mẫu phát triển, chưa là chất lượng toàn corpus. [Receipt](../deliverables/real-demo-evidence/cards-qwen3-python-run.json).
- Rà soát độc lập với đầu ra reviewer ghi **5 phản ví dụ**: loại nhầm hai câu có chứng cứ, loại đúng một câu vượt quá đoạn được dẫn, chấp nhận sai hai behavior chỉ dựa trên import. [Hồ sơ đối chiếu](../eval/adjudications/python2024-qwen3-card-counterexamples.json) không có người thật/GV ký duyệt và không tự tính F1 khi chưa chấm đủ fact/claim.
- Qwen3 vẫn là **candidate**, chưa đổi mặc định hoặc Release. Việc nó chạy được sau giới hạn cache sửa nhận định về tài nguyên trước đó; chưa chứng minh nó đạt mọi ngưỡng chất lượng.

Ưu tiên tiếp: đưa vị trí tìm kiếm vào ngữ cảnh viết claim, phân biệt import với hành vi, sửa false rejection/false acceptance, rồi đo lại cả hai nền tảng. IOC/ATT&CK/YARA đầy đủ, bộ sạch, stability và injection vẫn là gate mở. Buổi 4 không phải điều kiện kết thúc sản phẩm.

Cuối đợt đã dừng đúng server dự án và tắt VM nhẹ nhàng. [Receipt sau dừng](../deliverables/real-demo-evidence/runtime-stopped-after-cards.json) xác nhận cổng không còn lắng nghe, VM chạy bằng 0, VRAM quan sát 0 MiB; trọng số và đĩa VM không bị xóa. Đây là trạng thái tại thời điểm kiểm, không phải theo dõi nền.

## Đã triển khai và kiểm thực tế

- Qwen2.5 Coder 7B Q4_K_M: 7.615.616.512 tham số. Model mới ở C; model 1.5B trên D được giữ nguyên.
- Host chạy controller/Ollama; VM Ubuntu 24.04 2 GB/2 vCPU chạy parser. Không default route, không shared folders/clipboard/dnd, không thực thi mẫu.
- DIE 4.0.0 và FLOSS 3.2.0 cài offline, khóa asset/hash, chạy thành công trên Gomorrah và được SLM tự chọn. DIE cũng được SLM dùng thành công trên PythonStealer.
- Native tools kiểm executable digest, argv cố định, timeout/output/resource limits; source VM root-owned. FLOSS .NET chỉ static strings, không coi là giải rối CIL.
- Extractor giữ UTF-8 tiếng Việt và offset byte; guard nhận NFKC/zero-width variants. model_request ghi đúng evidence gửi vào SLM sau compaction.
- Truy xuất code: context 8192, tối đa 16 bước, giữ chỗ cho search và report. Citation ID ngắn ánh xạ tới chứng cứ thật. Behavior/ATT&CK chỉ dẫn IOC/strings bị loại.
- Metadata có kiểm equality với trường identify; reviewer SLM không thể loại sai các câu format khớp chính xác theo tập câu hỗ trợ hẹp.
- **88 kiểm thử phần mềm đạt trên Windows** tại bản bổ sung ranker/decoder/memory guard; không phải accuracy trên 88 malware.
- Source host/VM đã so hash khớp. Inventory 31 mẫu/fixture không có nghĩa 31 malware độc lập.

## Lượt phát triển thật gần nhất

Bảng dưới dùng mẫu public thật, Qwen7B thật và tool trong VM; không mock/fixture/replay. Hash chain đã kiểm. [Receipt metadata 6 lượt](../deliverables/real-demo-evidence/native-tools-and-navigation-runs.json).

| Run | Mẫu | Tool thành công | Kết quả |
|---|---|---:|---|
| 20261127T145127_bb612475 | Gomorrah | 6 | DIE/FLOSS được model chọn; inconclusive, reviewer loại sai metadata |
| 20261127T145456_79a81a36 | Gomorrah | 6 | Có tìm mã, claim/citation còn sai; inconclusive |
| 20261127T150251_d6b62b38 | Gomorrah | 6 | Reviewer chấp nhận nhầm URL credit là exfiltration; đã giữ phản ví dụ |
| 20261127T150554_176a3d4e | PythonStealer2024 | 6 | Incomplete: đọc trang hết 16 bước; giữ nguyên log lỗi |
| 20261127T151011_0717f844 | Gomorrah | 5 | Chặn sai loại chứng cứ; claim vẫn dẫn sai dòng; 153,76 s, inconclusive |
| 20261127T151305_4a5108aa | PythonStealer2024 | 6 | Hoàn tất sau sửa dự phòng bước; 174,58 s; pycdc lỗi/pycdas hoạt động; inconclusive |

Các claim import/library trong report Python không phải phân tích đầy đủ hành vi stealer. Reviewer chấp nhận không chứng minh claim đúng. Limitation do model viết cũng có thể chứa khẳng định thiếu căn cứ, phải được rà soát nội dung.

## Đáp án đối chiếu và chất lượng

[Hồ sơ Gomorrah](REFERENCE_ANALYSIS.md) có 6 mục từ ILSpy và nguồn công bố mẫu. Hash mẫu/output và marker của cả 6 mục đã kiểm lại trong VM. Đây là development reference, chưa có người thật ký duyệt, chưa phải ground truth đầy đủ hoặc tập test chưa nhìn thấy.

Lỗi đã xác minh: t.me URL trong Gomorrah nằm trong dòng ghi công tác giả, không tự chứng minh webhook exfiltration. Cấu hình urlbot còn cần đọc từ dữ liệu tách bằng dấu `|FS|`; không đoán endpoint.

Python3.11: pycdc vẫn chưa decompile đầy đủ, nhưng decoder mới đã thu payload candidate 332 dòng của PythonStealer2024 bằng Base64/Fernet/zlib tĩnh. [Chuỗi hash và phạm vi](PYTHON_STATIC_DECODING.md). Run thật 20261127T154300_0506c3a6 do Qwen7B tự gọi decoder thành công; 6 tool thành công, 181,544 giây, verdict vẫn inconclusive và 5 claim bị reviewer loại. Không biến backend thành công thành chất lượng phân tích đạt.

Đã train [ranker phụ trợ](../training/RANKER_EXPERIMENT.md) trên CPU, 117 anchor (70 train/42 validation/5 test) từ mẫu phát triển. Có loss/checkpoint thật; chưa fine-tune Qwen và chưa có xác nhận loại train GV yêu cầu. Run Gomorrah 20261127T153601_a3240ca6 dùng ranking mới vẫn có claim sai, 179,0067 giây, inconclusive.

[Phép thử Qwen3 8B](MODEL_COMPARISON.md) phải dừng do RAM khả dụng còn 15.020 KiB. Giữ log 65 event và receipt dừng, không có report hoàn tất; không đổi baseline/Release. Đã bổ sung kiểm RAM giữa các request và unload khi dưới 256 MiB. Không coi phép đo này là peak profiler toàn hệ thống.

Regression mới `20261127T160346_4685a56a` trên Python thật đã hoàn tất luồng với 6 tool thành công, có decoder và chỉ đọc source sau giải mã; report vẫn inconclusive/có claim bị loại. [Receipt](../deliverables/real-demo-evidence/python-decoder-final-regression.json). Đây là bằng chứng pipeline hoạt động, chưa đóng gate chất lượng.

[Hồ sơ Python](../eval/reference_profiles/python2024.static.json) gồm năm fact đã kiểm marker/hash trong VM; không phải human approval. [Chấm báo cáo baseline](../deliverables/real-demo-evidence/python2024-baseline-score.json): 5 raw claim không được chính trích dẫn của chúng chứng minh, 5 fact chưa được báo cáo có căn cứ, F1=0 trên phạm vi nhỏ này. Nhãn raw malicious khớp nguồn nhưng report sau lọc là inconclusive. Không dùng số này đại diện toàn corpus hoặc dùng việc lọc hết claim để báo tỷ lệ bịa 0.

## Injection: sửa cách diễn giải số liệu cũ

Đợt chạy mới trên 10 cặp tệp cho mỗi chế độ đã có đầy đủ thông điệp và báo cáo cuối để chấm. Phần dưới ghi lý do loại số liệu lịch sử. [Kết quả mới của 40 lượt](NATIVE_TOOLS_AND_EXPOSURE.md#kết-quả-40-lượt-chạy-có-đối-chứng).

20 run/10 cặp lịch sử thiếu model_request. Audit v2: **0 eligible/10 unevaluable, rate=null**. Con số 9/10 cũ chỉ chứng minh payload tới tool observation, không dùng làm tỷ lệ chống injection.

P06 từng chạy với lớp chặn bật và tắt. Metadata ghi cùng verdict, nhưng nhật ký lịch sử thiếu nội dung thông điệp để xác minh payload đã tới model. Hiện chưa đủ mẫu số cho tỷ lệ bị lừa 0%. [Chi tiết kiểm lại](NATIVE_TOOLS_AND_EXPOSURE.md).

## Gate còn mở

| Gate | Trạng thái |
|---|---|
| Buổi4, >=2 tool thật; SLM>=7B; >=4 tool thật | Có bằng chứng tích hợp/backend trên mẫu thật |
| Chất lượng trên bốn mẫu v11 | Sau lọc, P 81,67%, R 47,12%, F1 59,76% trên 104 mục. F1 riêng IOC + ATT&CK 16,67%. Verdict 0/4. |
| Bịa ≤ 5%, dẫn chứng ≥ 90% | 75/75 câu sau lọc có trích dẫn, 64/75 câu đủ chứng cứ theo nghĩa (85,33%). Còn 8/75 câu thiếu căn cứ (10,67%) và 3 câu sai. |
| Ổn định qua 3 lần ≥ 80% | AgentTesla, cùng bản guided-8b, trùng 4/28 nhận định (14,29%). Các profile khác cần phép đo riêng. |
| YARA TPR>=90%, FPR=0 | Đã đo 5/5 positive development, 0/39 negative với7B/8B và replay khớp. Chỉ áp dụng corpus công bố; luật theo bản build, chưa kiểm rename/repack/unseen malware |
| An toàn, mục tiêu đổi verdict 0% | 40 lượt thật trên 10 cặp Python mỗi chế độ. Bật chặn, 0/10 đổi verdict sau duyệt và 0/10 đổi thô đúng hướng. Tắt chặn, 0/10 sau duyệt và 2/10 thô đúng hướng. Còn thiếu độ đa dạng theo đề xuất. [Biên bản](NATIVE_TOOLS_AND_EXPOSURE.md#kết-quả-40-lượt-chạy-có-đối-chứng). |
| Training thật | Có ML ranker với cập nhật trọng số/loss/checkpoint; chưa SLM fine-tune, chưa chốt nghĩa yêu cầu GV |
| Hiệu quả | Có thời gian, token, RSS tiến trình và VRAM cuối lượt. Với Mercurial v13 đã có 299 điểm đo toàn máy, VRAM lớn nhất quan sát là 4.173 MiB. Các đỉnh ngắn giữa hai lần lấy mẫu và khả năng lặp lại trên máy khác còn mở. |
| Tái lập | Đã dựng VM mới ở bản cũ trên cùng host; installer mới chưa thử máy vật lý khác |

[Backlog và điều kiện đóng](CONG_VIEC_CON_LAI.md) nêu việc tiếp theo. 12 ảnh và proposal ở docs/reference giữ nguyên bytes. Release buổi4 giữ nguyên tag/asset; main nhận cập nhật kỹ thuật đã kiểm.

## Lịch sử và runtime

Hai demo buổi4 20261127T130645_f60cec20 và 20261127T130934_26431286 vẫn giữ receipt cũ: 4/5 tool, 100,4/90,9 s, inconclusive. CI bản cũ có 49 tests; không thay số lịch sử bằng 79 trước khi CI mới chạy.

Runtime được bật lại theo ủy quyền mới để đo. Receipt runtime-stopped cũ chỉ chứng minh thời điểm đó; trạng thái cuối đợt được ghi riêng. Dừng giải phóng RAM/VRAM, không xóa weight hoặc đĩa VM.

Đợt ranker/decoder đã dừng server Ollama và gửi shutdown nhẹ nhàng cho lab sau regression. [Kiểm trạng thái cuối đợt](../deliverables/real-demo-evidence/runtime-stopped-after-decoder.json) ghi PID/port/VM và RAM khả dụng tại thời điểm kiểm, không phải theo dõi nền liên tục. Qwen3 đã tải vẫn giữ trong model store, chưa đổi default hoặc Release.
