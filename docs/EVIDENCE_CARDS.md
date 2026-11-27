# Báo cáo theo từng đoạn chứng cứ

## Vấn đề cần giải quyết

Ở các run phát triển trước, Qwen 7B có thể diễn tả một hành vi có thật nhưng chọn dòng trích dẫn chưa chứa lời gọi chứng minh hành vi đó. Ví dụ, tên hàm nén và dòng khai báo đường dẫn chưa chứng minh thao tác tạo ZIP. Bộ kiểm tra quote chỉ chứng minh chuỗi tồn tại; reviewer dùng cùng SLM cũng có thể chấp nhận sai. Không thể dùng tỷ lệ quote hợp lệ làm tỷ lệ grounding ngữ nghĩa.

Nhánh `evidence-cards-v1` là thí nghiệm sửa phần báo cáo. Cấu hình nằm ở `config/host.cards-candidate.example.json`. Nó chưa thay thế cấu hình mặc định cho tới khi có bảng chấm đủ trên mẫu thật. Kết quả âm và báo cáo cũ được giữ.

## Luồng sản phẩm

1. ReAct vẫn để SLM chọn công cụ và câu tìm kiếm trong danh sách cho phép. Parser/ILSpy/pycdas/decoder chạy trong VM, mẫu không được thực thi.
2. Khi đủ điều kiện, SLM chọn `finalize`. Đây là thao tác của bộ điều phối, không gửi xuống VM và không tính là công cụ phân tích thứ hai/thứ tư.
3. Bộ điều phối lấy các đoạn từ chứng cứ **đã được truy xuất và đã qua guard**. Ưu tiên vị trí tìm kiếm và source candidate đã giải mã. Mỗi đoạn liên tục tối đa 32 dòng/4.600 ký tự; tối đa 10 đoạn trong cấu hình thử. Không nối qua dòng bị thiếu hoặc bị guard che.
4. Mỗi request chỉ yêu cầu tối đa hai nhận định cụ thể trên một đoạn. Không đoán dữ liệu đầu vào, mục đích, giao thức hay kết quả thực thi. Đoạn không có thao tác đủ rõ có thể trả về danh sách rỗng.
5. Mỗi nhận định được cùng SLM kiểm tra riêng với toàn bộ đoạn. Tất cả câu thô, câu bị loại, lý do và request/response đều có trong journal riêng tư.
6. Bộ điều phối gắn đúng toàn bộ đoạn đã gửi vào citation có `line`, `end_line`, `quote`. Kiểm tra cơ học dựng lại từng dòng, yêu cầu toàn bộ chuỗi khớp, cùng hash mẫu và tool thành công. Đây là dẫn chứng do giao thức đoạn quyết định, không sửa ngầm dòng mà model đã chọn.
7. SLM tổng hợp verdict từ các nhận định còn lại. Câu bị loại không đi vào bước này nhưng vẫn ở báo cáo/raw và mẫu số khi chấm. Mỗi verdict cần ID nhận định hỗ trợ. Bản thử không kết luận benign từ một tập đoạn hữu hạn.

Nhánh này hiện tập trung vào behavior/observation. IOC, ATT&CK và YARA đầy đủ vẫn là phần phải tích hợp/đánh giá tiếp; không được coi báo cáo đoạn là sản phẩm cuối chỉ vì câu văn hoặc dẫn chứng tốt hơn.

## Dữ liệu và kiểm chứng

- `events.jsonl`: hash chain, phiên bản source, thao tác thật, đoạn được gửi, phản hồi và telemetry. Request báo cáo lưu cả nội dung chính xác và SHA256; không đưa file này công khai vì có thể chứa endpoint/credential của mẫu.
- `report.card-candidates.json`: mọi câu trước tổng hợp verdict. Nếu request cuối lỗi, các câu đã tạo vẫn có trong journal; nếu giai đoạn tạo hoàn tất thì có cả file này.
- `report.model-raw.json`: toàn bộ nhận định đề xuất, verdict được tổng hợp từ tập được giữ; phương pháp khác baseline phải ghi rõ khi so sánh.
- `report.private.json`: báo cáo cuối, câu bị loại, giới hạn và số đo. `requires_semantic_review` vẫn true.
- Báo cáo sau lọc không thay thế điểm của báo cáo thô. Việc loại hết câu không tạo ra hallucination=0 hay accuracy=100%.

Kiểm thử dùng fixture vô hại để kiểm giao thức và lỗi biên; demo chất lượng phải dùng mẫu public thật. Không trộn hai loại bằng chứng. Các kiểm thử gồm khoảng dòng sai, thiếu dòng giữa, quote bị đổi, mẫu khác, guard che dòng, giới hạn kích thước, không gửi finalize xuống công cụ và giữ câu bị loại.

## Cách chạy thí nghiệm thật

Trong PowerShell ở thư mục dự án, sau khi cài môi trường và có VM đúng cấu hình:

```powershell
.\scripts\Start-Lab.ps1
$env:STEALER_LAB_TOKEN=(Get-Content -LiteralPath config/lab.token -Raw).Trim()
.\.venv\Scripts\python.exe agent_react.py --config config/host.cards-candidate.example.json --sample public_python2024.bin --public-demo --live
.\scripts\Stop-Lab.ps1
```

Đổi sample thành `public_gomorrah.bin` để kiểm nhánh .NET. Lệnh chạy agent ở host chỉ gửi ID mẫu; tool server trong VM mới mở mẫu. Không mở hoặc chạy file mẫu trên Windows host. Cấu hình mặc định và lịch sử trước đó được giữ để đối chiếu.

Để so prompt/model với **cùng đặc trưng đã thu**, có `scripts/replay_card_report.py --run <ID> --config config/host.cards-candidate.example.json --cards 3`. Nó kiểm hash chain rồi gọi SLM thật trên các đoạn model-visible đã lưu; kết quả ở `private/report-experiments`. Không có mock model, nhưng cũng không có tool/VM được gọi mới: đây là phép thử thành phần, **không dùng làm demo end-to-end** hay bằng chứng agent tự điều phối lại công cụ. Chỉ sau khi sửa có ích mới chạy lại `agent_react.py` trên mẫu thật để nghiệm thu luồng.

## Giới hạn của thiết kế

Dẫn nguyên đoạn giải quyết lỗi chọn sai dòng nhưng không tự chứng minh câu đúng nghĩa. Nhiều request nhỏ tăng thời gian/token. Tập đoạn có thể bỏ sót chuỗi dữ liệu trải qua nhiều hàm. Reviewer cùng model có lỗi tương quan với generator; kiểm ngữ nghĩa này không phải đáp án độc lập. Gắn một câu với cả đoạn lớn cũng cần xem đoạn có chứng minh đầy đủ từng thành phần câu không.

Mỗi request báo cáo đều kiểm RAM giữa các lần gọi như giai đoạn ReAct. Đây không phải peak monitor liên tục. Model/VM chỉ bật cho thực nghiệm và được dừng cuối đợt; weight và đĩa VM giữ nguyên.

## Phát hiện tài nguyên trong lúc kiểm thử

Hai run đầu `20261127T162609_6cc4fabf` (context 8192) và `20261127T162906_8b0aad52` (context 4096) dừng do RAM khả dụng xuống dưới 256 MiB; chúng không có báo cáo đoạn hoàn tất. Log runtime lần thứ hai ghi cache 14 prompt chiếm 2.277,509 MiB, trần 8.192 MiB. Chỉ giảm context chưa giải quyết được cache tích lũy giữa các request.

`Start-LocalModel.ps1` nay đặt `LLAMA_ARG_CACHE_RAM=256` riêng cho tiến trình Ollama dự án, có tham số `-PromptCacheMiB` và ghi giá trị trong process receipt. Đây là cache prompt giữa các request, khác với cửa sổ context/KV của một request. Hỗ trợ biến môi trường được xác nhận bằng `llama-server.exe --help` của runtime đang cài và [tài liệu llama.cpp chính thức](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md). [Issue upstream Ollama](https://github.com/ollama/ollama/issues/18264) mô tả cùng loại bộ nhớ tăng; log thực tại máy mới là bằng chứng của ca dự án này.

Giới hạn này không cập nhật trọng số, không xóa model và không thay cấu hình Ollama toàn hệ thống. Sau khi đổi phải khởi động lại đúng server dự án; kiểm log runner để xác nhận giá trị được áp dụng. Hiệu quả và tốc độ cần đo ở run hoàn tất, không suy từ giá trị cấu hình.

Sau giới hạn cache, run Qwen2.5 Coder 7B `20261127T163251_1a980ae2` (Python) hoàn tất 130,1182 s, RAM khả dụng thấp nhất giữa request 1.335.648.256 B; run `20261127T163540_fed8503b` (Gomorrah) 136,3791 s, 968.679.424 B. Cả hai có 6 công cụ thành công nhưng **0 claim**: model chọn danh sách rỗng ở mọi đoạn. Không dùng kết quả rỗng để báo tỷ lệ bịa bằng 0; verdict vẫn inconclusive. [Receipt của bốn run, gồm hai run dở](../deliverables/real-demo-evidence/cards-qwen25-runs.json).

Phép thử thành phần Qwen3 8B trên 3 đoạn Python đã lưu (`20261127T163819_c14eac1d`) tạo 6 claim; reviewer chấp nhận cả 6, nhưng rà soát phát hiện 2 câu nhầm hash trong metadata giải mã thành đối số của lệnh mã độc. Đây là lỗi thật, không phải đáp án đúng. Đã sửa bộ chọn đoạn để loại các dòng provenance của decoder theo `source_line`, kể cả header dài bị tách ra nhiều dòng chứng cứ; không dùng lại wrapper/bytecode làm source khi đã có payload candidate. Một kiểm thử mới bao phủ lỗi này. Run dùng bản trước/sau sửa phải phân biệt bằng source hash; không suy chất lượng end-to-end từ phép thử thành phần.

Run end-to-end sau sửa `20261127T164056_2bc4e796` dùng Qwen3 8B/context4096, tự gọi bốn backend thành công trên Python thật và tạo 12 claim trong 6 đoạn. Reviewer giữ 9 câu; verdict malicious, tổng thời gian 376,1841 s. Nhánh dùng `config/host.cards-qwen3-candidate.example.json`; đây vẫn là cấu hình thử, model Qwen3 chưa nằm trong Release mặc định. [Receipt](../deliverables/real-demo-evidence/cards-qwen3-python-run.json) và [phản ví dụ reviewer](../eval/adjudications/python2024-qwen3-card-counterexamples.json) phải đọc cùng nhau. Các claim về import HTTP/SMTP vẫn bị gán thành behavior; không coi một verdict trùng nhãn là chứng minh lập luận đúng.

File counterexamples chỉ rà năm nhận định cụ thể, không phải bảng chấm đủ 12 câu và năm fact đối chiếu. Không đưa nó vào `eval/score.py` như một benchmark đầy đủ hoặc tính các dòng chưa được chấm là đúng/bỏ sót. Cần hoàn thành đối chiếu toàn bộ trước khi công bố Precision/Recall/F1.
