# Qwen thấy gì khi nhóm chấm một mẫu?

Người vận hành cần biết mình đã chọn tệp nào. Qwen chỉ cần một mã để yêu cầu VM phân tích đúng tệp đó. Nếu đưa tên như `clean_ms_addinprocess.bin` vào prompt, chữ `clean` đã gợi ý nhãn chấm. Bản web hiện tại dùng `case.bin` cho mọi tệp nhị phân trong lượt điều tra chính.

## Demo trên máy nhóm

1. Khởi động bằng `.\scripts\Start-Web.ps1` trong PowerShell tại gốc dự án. Mở `http://127.0.0.1:4180` và kiểm tra trạng thái Ollama cùng VM.
2. Chọn mẫu, bấm **Chạy điều tra** và ghi mã lượt hiện trên tab **Nhật ký**. Khi hoàn tất, mở **Model thấy tên mẫu nào?** tại tab này. Giao diện đọc lại nhật ký để đếm số yêu cầu chứa tên gốc hoặc nhãn nguồn dữ liệu trong tin nhắn, schema và trích đoạn.
3. Mở **Hỏi đáp** và hỏi “Vì sao verdict của lượt này vẫn chưa đủ bằng chứng để kết luận?”. Qwen chọn chủ đề. Khi câu hỏi được xếp vào chủ đề verdict, ứng dụng tra quyết định cuối, các vai trò đã kiểm và đúng những nhận định báo cáo dẫn. Bấm mã câu để mở nhận định. Bấm **Xem đoạn mã đã dẫn** để xem dòng nguồn. Những lượt cũ thiếu danh sách dẫn chứng có thông báo riêng.
4. Để yêu cầu điều tra tiếp, mở một đường nối trên **Bản đồ chứng cứ**, chọn **Hỏi tiếp về đường nối này** rồi **Tra cứu chứng cứ**. Nếu còn thiếu chứng cứ và có mã nguồn khả dụng, agent chọn truy vấn cho công cụ tìm trong VM. Nhật ký câu hỏi tách lần chọn chủ đề, lần chọn truy vấn và kết quả VM. Sau demo, chờ tác vụ cuối hoàn tất rồi bấm **Tắt lab**.

## Ràng buộc giữa tên, tệp và nhật ký

Mỗi lượt chỉ có một tệp được phép phân tích. Web truy tên thật trong danh mục để ghim SHA-256. Prompt mở đầu, trạng thái ReAct và schema hành động dùng cùng mã trung tính. Sau khi xác nhận lựa chọn của Qwen, bộ điều phối tạo đối số riêng cho VM. VM trả tên và SHA-256 qua từng quan sát. Các điểm trích dẫn vẫn dùng số dòng và mã băm đầu ra gốc.

Trước mỗi lần gọi Qwen trong phân tích chính, kể cả các bước viết và duyệt, bộ điều phối dò tên đăng ký (gồm cả phần trước đuôi tệp) và hai giá trị phân loại nguồn dữ liệu trong nội dung sắp gửi. Nếu phát hiện, lượt dừng trước khi suy luận. Mã sinh viên chọn trên giao diện, nhãn chấm, bản ghi ánh xạ và dữ liệu VM vẫn có trong nhật ký riêng. Những dấu vết nội tại như tên thư viện, API và chuỗi ngữ cảnh có thể giúp nhận ra chương trình.

Lệnh sau kiểm chuỗi băm, nội dung yêu cầu, schema, lựa chọn của model, đối số thực gửi tới VM và định danh của quan sát. Đối với lượt bị gián đoạn, cần đọc riêng số yêu cầu, phản hồi, lệnh gửi và quan sát. Phép so yêu cầu cùng hash mẫu, digest model và cấu hình ngoài tùy chọn đặt tên.

```powershell
.\.venv\Scripts\python.exe -m eval.model_identity --pair 20261128T124233_ca348a88 20261128T132044_0180f1cd
```

Các mã lượt trong tài liệu dùng được trên máy giữ nhật ký tương ứng. Trên máy thành viên, chạy một lượt mới để kiểm đầu vào thực tế của máy đó. CLI dùng `--public-demo` bật mã trung tính mặc định. Khi cần tái lập cách đặt tên cũ để làm đối chứng, thêm `--show-registry-id`. [Mã điều phối](../stealer_agent/engine.py) · [Mã kiểm nhật ký](../eval/model_identity.py)

## Cách tính điểm

Nhãn quy ước của nhóm cho chương trình Microsoft có chữ ký là `benign`, cho PythonStealer là `malicious`. Mỗi tệp chiếm một vị trí trong mẫu số. Chỉ cộng điểm khi lượt hoàn tất và verdict khớp nhãn. `suspicious` và `inconclusive` đều được tính là chưa kết luận đúng. Việc làm ẩn tên giải quyết một nguồn lộ nhãn của bộ điều phối. Chấm khả năng tổng quát hóa còn cần tệp chưa dùng phát triển và người đối chiếu độc lập.

## Hai lượt chạy lại trên web

| Mẫu và mã lượt mới | Verdict trước → sau | Tin nhắn lộ tên trước → sau | Lượt model mới | Quan sát VM khớp hash | Thời gian mới |
|---|---|---|---:|---:|---:|
| Microsoft AddInProcess .NET · `20261128T132044_0180f1cd` | inconclusive → inconclusive | 18 → 0 | 27 | 17/17 | 272,37 s |
| PythonStealer · `20261128T132617_7af6d50a` | suspicious → suspicious | 18 → 0 | 45 | 17/17 | 417,59 s |

Cả hai lượt cũ còn có tên mẫu trong 17 schema hành động. Hai lượt mới có 0 lần xuất hiện ở cả ba trường đã dò. Tất cả dùng cùng digest Qwen3 8B. Cặp .NET dùng hai phiên bản tổng hợp báo cáo khác nhau (16 và 17), cặp Python cùng bản 17. Bốn lượt trên hai mẫu phát triển chưa đủ để quy thay đổi điểm hoặc thời gian cho việc đổi tên. Verdict đúng sau khi làm ẩn tên đạt **0/2**. Trong **Đánh giá**, mở **Chấm verdict khi model chỉ thấy mã mẫu trung tính** để xem cả bốn hàng. [Bảng từng lượt đã kiểm từ nhật ký](../deliverables/real-demo-evidence/model-identity-comparison.json)

Trên Python, công cụ pycdc trả lỗi. VM tiếp tục đọc bytecode bằng pycdas và bộ giải mã tĩnh. Chấm các nhận định giữ lại theo 36 ý tham chiếu cho kết quả **20 đúng, 16 bỏ sót, 0 sai, 0 thiếu căn cứ**. Precision là 100%, recall 55,56%, F1 71,43%. Lượt cũ cùng bản tổng hợp đạt 21/36, F1 72,41%. Câu C3 của lượt mới được đối chiếu riêng với vị trí gán tên máy chủ và vị trí dùng giá trị đó. [Điểm và tọa độ các trích dẫn đã mở](../deliverables/real-demo-evidence/transfer-live-20261128T132617_7af6d50a.json)

Đã mở mục kiểm tên mẫu trên trình duyệt với khung rộng 390 px và 1.360 px cho cả hai lượt. Câu hỏi verdict mở được C1 trên từng báo cáo, với 3 đoạn nguồn trong câu trả lời .NET và 25 đoạn trong câu trả lời Python. Ở lượt Python, bấm hỏi tiếp về mắt xích **Xử lý dữ liệu → Ghi ra tệp** đã khiến Qwen chọn truy vấn mới. VM trả 3 kết quả khớp và giao diện mở được dòng trong số hai vị trí có trích dẫn. Các kết quả tìm kiếm là đầu mối để kiểm chứng đường nối. Bản câu hỏi .NET đầu tiên chạy trên tiến trình web cũ trả 0 nguồn. Nhật ký giữ cả lần đó và lần kiểm thành công trên tiến trình đã nạp mã mới. [Nhật ký tóm tắt .NET](../deliverables/real-demo-evidence/web-20261128T132044_0180f1cd.json) · [Nhật ký tóm tắt Python](../deliverables/real-demo-evidence/web-20261128T132617_7af6d50a.json)

Trên bản clone của nhóm, `python -m eval.model_identity` đối chiếu bảng công bố với các biên bản rút gọn. Để tính lại số lần lộ tên từ chính nội dung từng yêu cầu trên máy giữ nhật ký, truyền mã lượt, ví dụ `python -m eval.model_identity 20261128T132617_7af6d50a`.
