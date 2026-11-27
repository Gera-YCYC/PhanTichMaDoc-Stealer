# Lựa chọn SLM qua phép thử thực tế

Model mặc định vẫn là **Qwen2.5 Coder 7B Q4_K_M**, 7.615.616.512 tham số, digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`. Đây là baseline đáp ứng ngưỡng >=7B của hướng 6, đã có log dùng ILSpy, pyinstxtractor, pycdas, DIE/FLOSS và decoder. Đáp ứng kích thước model không đồng nghĩa đạt chất lượng phân tích.

Model 1.5B ban đầu trên D không đủ ngưỡng hướng 6, được giữ nguyên theo yêu cầu người dùng. Các model mới nằm trong `private/ollama-models` trên C. Tải weight và chạy inference không phải train.

## Phép thử Qwen3 8B

Lượt Python v9 đầu-cuối mới mất495,9s và còn5/18 câu raw thiếu căn cứ; score nguyên tử trên34 đơn vị là P 77,27%, R 50%, F1 60,71%. Bản v10 giới hạn IOC và sửa nhãn API; lượt đầu-cuối dừng do RAM trước report. Khi tắt VM để kiểm riêng report trên đúng đoạn source v9,8B sinh12/12 câu có căn cứ nhưng Recall44,12%, F1 61,22%, không có ATT&CK, reviewer loại nhầm2 câu. Chưa đủ để đổi mặc định hoặc kết luận8B tốt hơn toàn hệ thống. 202,5s report-stage không được so với495,9s đầu-cuối như cùng khối lượng công việc. [Bằng chứng và giới hạn](OPERATIONS_CONTEXT_V9.md).

Thử nghiệm hẹp mới có messages/schema Python giống hệt, cùng manifest23file host: 8B chọn6/6 thao tác đúng trong39,5081s,7B chọn4/6 trong33,8093s và loại nhầm hai. Trên29 đơn vị nguồn đã công bố, Recall chỉ20,69%/13,79%, F134,29%/24,24%. Không đủ để thay model mặc định hoặc coi8B giải được toàn bài. .NET8B10/10 câu upload/response đúng nhưng chưa có Recall/F1. [Chi tiết, snapshot và giới hạn](ATOMIC_REPORT_STAGE.md). Đây là reporting replay, không phải chạy mới toàn bộ ReAct/VM.

Luồng YARA corpus đã có phép so riêng cùng core/corpus/context4096/seed42/num_predict1800: 7B hoàn tất trong42,5242s (6247/394token), 8B73,0389s (6287/485token), cả hai5modelcall, 5/5positive và0/39negative báo nhầm, replay khớp. Chọn7B có sẵn làm mặc định **chỉ cho luồng YARA này**, chưa kết luận hơn/kém ở báo cáo hành vi. Một lượt mỗi model, chưa đo độ lệch tốc độ. [Receipt và thiết kế](YARA_REAL_CORPUS.md).

Thí nghiệm v8 giữ Qwen2.5 Coder 7B là baseline/Release, chưa thay bằng 8B. Lượt 7B có query từ source `20261127T210746_9922cc4e` hoàn tất điều phối trong 162,2 s nhưng trả 0 nhận định trên 9 card. Lượt 8B `20261127T211223_9602dfdd` tạo 11 câu trong 484,7 s, source audit chấm 8 đúng/3 thiếu căn cứ; verdict suspicious. Các lần này khác một sửa trạng thái báo cáo rỗng, không coi là benchmark kiểm soát hoàn toàn. Bản 8B còn một lượt trước đó bị giới hạn RAM ngắt. [Kết quả và phạm vi](OPERATIONS_CONTEXT_V8.md), [điểm đầy đủ](../deliverables/real-demo-evidence/python2024-operations-v8-claim-score.json).

Metadata/API fact tốt hơn không bảo đảm model sinh hoặc duyệt câu chính xác hơn. Không chọn model chỉ vì lớn hơn, trả nhiều câu hơn hoặc tự duyệt giữ nhiều câu hơn; phải so chất lượng, bỏ sót và tài nguyên trên cùng corpus/revision. Model 8B chưa đưa vào Release vì chưa đủ bằng chứng thay baseline.

Nguồn [Ollama Qwen3:8b](https://ollama.com/library/qwen3:8b): Q4_K_M, 8.190.735.360 tham số. Download thực tế 5.225.388.164 byte, digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`. Dùng cùng endpoint cục bộ và `think=false` theo [Ollama chat API](https://docs.ollama.com/api/chat), context 8192. Không tải dữ liệu mẫu lên dịch vụ model.

Run `20261127T154828_a39039e6` trên PythonStealer2024 đã phải dừng chủ động sau 15 tool action vì máy thiếu RAM. [Receipt dừng riêng](../deliverables/real-demo-evidence/qwen3-8b-aborted.json) giữ hash journal 65 event, metadata model và số đo:

| Số đo tại thời điểm kiểm | Giá trị |
|---|---:|
| RAM vật lý khả dụng | 15.020 KiB, khoảng 14,7 MiB |
| RAM vật lý hệ điều hành thấy | 12.283.768 KiB |
| Runtime model theo Ollama | 6.599.978.515 byte |
| Phần VRAM theo Ollama | 4.190.623.498 byte |
| GPU | RTX 3050 Laptop 6 GB |

Đây là một mẫu đo trong quá trình chạy, không phải peak profiler đầy đủ. Lượt thử **không có báo cáo hoàn tất**, không được chấm là thất bại phân loại hay 0% hallucination. Log còn nguyên, receipt bên ngoài giải thích Ctrl-C do áp lực RAM. Sau dừng server, RAM khả dụng đo lại khoảng 4 GiB khi VM vẫn bật.

Qwen3 chưa được chọn làm mặc định và không được đưa vào Release cũ. File đã tải vẫn giữ cục bộ, không tự xóa. So sánh này chỉ cho thấy cấu hình 8B/context8192 cùng tải máy tại thời điểm đó không phù hợp; không tuyên bố Qwen3 luôn kém hơn hoặc không thể chạy ở cấu hình khác. Controller có thay đổi giữa hai lượt nên đây không phải A/B thuần model cho accuracy.

## Hướng tiếp theo

1. Giữ 7B làm baseline đã đo trên máy hiện tại; giảm dữ liệu không liên quan trước khi tăng model.
2. Chặn vòng inference tiếp theo khi RAM khả dụng dưới 256 MiB; ghi `ResourceBudgetExceeded` và thử unload đúng model cục bộ. Đây là kiểm giữa các request, không ngăn mọi đỉnh bộ nhớ bên trong một request.
3. Trước thử model/config khác, chốt benchmark và revision, ghi đủ cả kết quả dở/lỗi. Tối ưu context/cache phải được đo lại, không đoán sẽ đủ VRAM.
4. Số liệu 7B hiện vẫn có inconclusive và claim sai; chưa có cơ sở tuyên bố đạt F1/verdict cuối môn.

Script tải candidate `scripts/pull_model_candidate.py` là thao tác so sánh có chủ đích; quy trình Setup-Team mặc định không tải thêm 8B. Không đổi tag hoặc phân phối model mới trước khi có bằng chứng hữu ích.

## Cập nhật chẩn đoán cache

Trong thí nghiệm báo cáo đoạn sau đó, runtime 7B cũng tăng RAM theo từng request. Log xác nhận cache prompt lưu các lượt cũ đạt 2.277,509 MiB ở một quan sát và 2.679,6 MiB lớn nhất trong log, trần mặc định 8.192 MiB. Đã đặt cache riêng của server dự án xuống 256 MiB bằng biến được runtime hỗ trợ, xem [bằng chứng và cách áp dụng](EVIDENCE_CARDS.md#phát-hiện-tài-nguyên-trong-lúc-kiểm-thử). Vì vậy không thể quy riêng lần thiếu RAM của Qwen3 cho số tham số 8B.

Lần thử mới `20261127T164056_2bc4e796` đã hoàn tất với Qwen3 8B/context4096 trên Python thật: 376,1841 s, RAM khả dụng thấp nhất đo giữa request 815.947.776 B. Báo cáo có 12 claim/9 được reviewer giữ, nhãn malicious khớp mẫu, nhưng đã xác định false acceptance/false rejection. Đây là khả năng chạy thật và một điểm kiểm chất lượng, chưa là benchmark A/B đầy đủ; 7B vẫn là mặc định, 8B vẫn candidate. [Receipt và giới hạn](../deliverables/real-demo-evidence/cards-qwen3-python-run.json).
