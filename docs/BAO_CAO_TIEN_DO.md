# Báo cáo tiến độ đồ án Phân tích mã độc

**Đề tài:** Xây dựng AI Agent phân tích mã độc đánh cắp thông tin (Stealer) .NET/Python theo mô hình ReAct sử dụng SLM cục bộ.

**Phạm vi tài liệu lịch sử:** bản tích hợp buổi 4. Mục tiêu hiện tại đã chuyển sang hoàn thiện toàn sản phẩm; xem STATUS.md và PROJECT_GOAL.md. Không cần tên/MSSV hay bìa báo cáo để xây dựng sản phẩm.

## 1. Bài toán và mục tiêu

Stealer có thể được viết bằng .NET hoặc Python rồi đóng gói thành chương trình thực thi. Người phân tích cần xác định loại file, phục hồi mã/bytecode, tìm dấu hiệu thu thập dữ liệu và kênh gửi, trích IOC, đối chiếu MITRE ATT&CK và đề xuất luật phát hiện. Đồ án bổ sung một agent dùng SLM để lựa chọn công cụ, đọc quan sát và ghi nhận nhận định có dẫn chứng.

Slide quy định buổi 4 gọi được ít nhất hai công cụ; buổi 6 có ít nhất ba mẫu và log; buổi 8 hoàn chỉnh cùng bảng đánh giá. Ngưỡng cuối gồm P≥0,8, R≥0,7, F1≥0,75 (nhắm F1≥0,8), verdict đúng toàn bộ tập lab, hallucination≤5%, grounding≥90%, stability≥80%, YARA TPR≥90%/FPR=0 và injection success=0%. Mọi ngưỡng chưa có dữ liệu đủ giữ trạng thái chưa xác nhận.

## 2. Đánh giá mã nguồn ban đầu

Repo bạn được giữ ở `audit/friend-repo` và đối chiếu tại commit `9362d1c0c8455bb15ff089c4b7c0bbc5b0f356f4`. Audit phát hiện một số đường chạy có thể kết luận lành khi thiếu công cụ/lỗi, chấp nhận claim không có chứng cứ, và nhầm kiểm tra fallback với backend thật. Báo cáo cùng probe nằm ở `audit/`.

Do đó, dự án dùng lại ý tưởng chia tool và mục tiêu demo, nhưng xây lại điều phối, contracts, VM boundary, error handling, kho bằng chứng và phép đo. Phần này được giải thích cụ thể trong `REUSE_DECISIONS.md`; không ghi nhận repo cũ là đã đạt tiêu chí chỉ dựa vào README.

## 3. Môi trường đã dựng

Máy thật i5-12450HX, RAM khoảng 12 GB, RTX3050 6 GB. Model cũ trên D là Qwen2.5 1.5B, thấp hơn yêu cầu 7B của hướng 6. Với quyền tải model mới, bản chính dùng Qwen2.5 Coder 7B Q4_K_M trên C, metadata ghi 7.615.616.512 tham số. Kho cũ trên D còn nguyên. Ollama chạy loopback cổng 11435, không gọi LLM cloud.

VM Ubuntu 24.04 riêng dùng 2 GB/2vCPU để phù hợp RAM. Mạng host-only VMnet1, không default route, chia sẻ folder và clipboard tắt. Host gửi ID mẫu/tool; VM giữ và phân tích file. Thay lựa chọn Windows/FLARE-VM của đề xuất bằng Linux chỉ áp dụng cho phạm vi tĩnh. Bản hiện tại chưa có phân tích động Windows.

`scripts/verify_lab.py` kiểm lại nguồn code host/VM, metadata model, SHA256/size/mode mẫu và thiết lập cách ly. Receipt thật ở `evidence/local/lab-verification.json`.

## 4. Thiết kế đã thực hiện

Các module host gồm contracts, transport, engine, journal, security, grounding, reviewer, reporting và telemetry. VM có service/runner, pefile, ILSpy, strings ASCII/UTF16, AST, IOC, unpack PyInstaller, pycdc, pycdas và YARA. `KIEN_TRUC.md` mô tả ranh giới và xử lý lỗi.

SLM chọn từng tool trong schema hợp lệ. Controller không cho đổi mẫu, không cung cấp shell tự do, không cho finish trước khi đủ công cụ bắt buộc. Kết quả có ID và dòng chứng cứ, hash mẫu/output và backend. Lỗi/unavailable giữ riêng; không biến lỗi thành verdict benign.

Nhật ký lưu response của model, hành động dispatch, raw observation trong phạm vi đặc trưng/excerpt, dữ liệu model-visible, claim bị loại, token/time/memory. `reason` là mục đích hành động ngắn. Kho mẫu và raw bytecode không gửi vào SLM.

## 5. Bộ dữ liệu

Người dùng xác nhận giảng viên không phát mẫu I/J, nên nhóm tự chọn bộ công khai. Mẫu I/J trong slide vẫn giữ như yêu cầu nguồn tham chiếu, không đổi tên các mẫu public thành mẫu GV.

- Gomorrah .NET, 85.041 B, kho nghiên cứu jstrosch, ILSpy đọc được.
- AgentTesla .NET, 608.768 B, cùng kho nghiên cứu, có mô tả SMTP và log chạy agent.
- LunaGrabber, 23.250.383 B, MalwareBazaar, xác minh PyInstaller/Python3.11; pycdc phát diagnostics.
- PythonStealer 2024, 22.183.360 B, MalwareBazaar, PyInstaller/Python3.11; chưa phục hồi source đầy đủ.
- Mercurial 43.008 B là ứng viên bổ sung; metadata nguồn ghi MSIL, không dùng tên họ để suy ra Python.

`DATASET.md` có link nguồn và toàn bộ SHA256. Archive được chuyển qua RAM trên host, giải nén và xác minh trong VM. Mẫu chưa được thực thi. Khóa MalwareBazaar nằm trong file local được loại khỏi Git, không đưa vào báo cáo.

Fixture LabFixture.dll và safe_bundle.bin là dữ liệu lành tự tạo để kiểm toolchain. safe_bundle là ELF/PyInstaller Linux, không đại diện mẫu Windows J. Các phép đo trên fixture phải tách khỏi phép đo trên public malware.

## 6. Kết quả thực tế và phản ví dụ

Tổng duyệt mới chỉ dùng mẫu public thật: Gomorrah run 20261127T130645_f60cec20 gọi thành công 4 công cụ/100,3992 s; PythonStealer run 20261127T130934_26431286 gọi thành công 5 công cụ/90,9349 s. Cả hai dùng SLM 7B thật, VM thật và hash mẫu khớp manifest; nhật ký đã kiểm hash chain. Python có lỗi pycdc và fallback pycdas. Hai verdict vẫn inconclusive, một claim mỗi run bị loại. Receipt: deliverables/real-demo-evidence/receipt.json. Các phép thử fixture bên dưới giữ vai trò kiểm phần mềm, không dùng làm demo mã độc thật.

Bốn lượt trong `evidence/local/milestone4-latest.json` ghi nhận 4–5 công cụ phân tích thành công mỗi lượt. Các hash chain tương ứng được kiểm lại. Đây là bằng chứng cho điều kiện kỹ thuật buổi 4, không phải chứng nhận chất lượng toàn đồ án.

Các run giữ nguyên cả lỗi. Mẫu PyInstaller lành tính đi qua unpack và pycdc, trong khi Python public 3.11 gặp diagnostics và có lần hết ngân sách trước khi đọc bytecode fallback. Agent đôi khi đưa nhận định chỉ dựa vào metadata hoặc chọn chứng cứ chưa đúng. Lớp reviewer cùng SLM vượt qua regression nhỏ nhưng đã loại sai cả câu định dạng .NET đúng; điều đó chứng minh không thể dùng reviewer làm đáp án.

YARA đã compile/test thật. Luật sinh từ lựa chọn literal/condition của SLM qua renderer xác định. Run `yara_f8db42dbd9c5` có holdout marker fixture TPR=0 và FPR=0, với một positive/hai negative. TPR không đạt. Bộ này không phải tập đo malware accuracy và không còn là holdout chưa biết sau khi đã xem kết quả.

Ba run cũ trên cùng fixture/model cho stability exact-wording 0 và verdict không thống nhất. Các run này có phiên bản controller cũ; cần đo lại bản đã chốt. Chưa có P/R/F1/hallucination được chấm độc lập trên toàn bộ bộ public.

## 7. Phương pháp đánh giá

Mỗi nhận định thô được gán đúng, sai, bịa hoặc bỏ sót đối chiếu nguồn thật. Các claim bị guard/reviewer loại vẫn giữ trong đánh giá output thô. Tính P=Đúng/(Đúng+Sai+Bịa), R=Đúng/(Đúng+Bỏ sót), F1=2PR/(P+R). Mẫu số rỗng trả null.

Grounding cần câu trích thực sự hỗ trợ claim, không chỉ trùng ký tự. Verdict inconclusive không được tính đúng trên mẫu có nhãn benign/malicious. Stability đo đúng ba lần cùng SHA mẫu, model digest và nên cùng phiên bản code. Bộ injection cần chạy cặp có/không câu chèn; file không chạy xong hoặc không được phơi nhiễm payload phải ghi riêng, không tính là chống được.

`eval/review-worksheet.json` và `PHIEU_DANH_GIA.md` chứa nhận định đã trích từ log, chưa gán nhãn thay nhóm. `eval/score.py` yêu cầu reviewer và truth_reference để hạn chế điểm không có nguồn.

## 8. Công việc tới mốc sau

Ưu tiên chốt nhánh Python public và ground truth: phục hồi đủ logic hoặc ghi phạm vi bytecode một cách kiểm chứng được; chưa dùng khả năng unpack làm bằng chứng đã hiểu hành vi. Sau đó cải thiện chọn chứng cứ/độ bao phủ của báo cáo, chấm các nhận định và đo lại ba lần. Tại mốc lịch sử này chưa tích hợp DIE/FLOSS; đợt sau đã có backend thật, xem STATUS. YARA cần bộ positive/negative phù hợp, tách development/holdout mới. Bộ guard cần mở rộng từ fixture lành sang ca yêu cầu agent đổi malware thành benign.

Thông tin sinh viên không là điều kiện kỹ thuật của sản phẩm. Nhóm có thể tự thực hành demo/vấn đáp từ các module đã có. Slide tiến độ, tài liệu và mã nguồn có sẵn trên C. Video thật chưa ghi. Không tự push hoặc công bố mẫu/key.
