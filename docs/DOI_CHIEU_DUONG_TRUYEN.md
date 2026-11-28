# Kiểm chứng đường truyền trong báo cáo chính

Một lời gọi đọc tệp và một lời gọi gửi thư có thể nằm trong cùng mẫu mà dùng hai dữ liệu khác nhau. Agent giữ riêng hai câu hỏi. Đối số nào đi vào hàm gửi? Có truy ngược được đối số đó đến dữ liệu nhạy cảm ban đầu không? Báo cáo giữ lại mắt xích đã chứng minh và ghi rõ phần còn thiếu. Đây là phân tích tĩnh. Ngay cả một liên kết đầy đủ trong mã cũng chưa chứng minh máy nạn nhân đã thực thi hoặc máy chủ đã nhận dữ liệu.

## Demo trên máy đã dựng lab

1. Từ thư mục chứa `agent_react.py` trên máy Windows, chạy `.\scripts\Start-Web.ps1`. Mở `http://127.0.0.1:4180` và kiểm tra trạng thái Ollama cùng VM trên thanh đầu trang. Trên máy mới, làm theo [hướng dẫn dựng lab](TEAM_SETUP.md).
2. Chọn `public_python2024.bin`, bấm **Chạy điều tra** rồi mở **Nhật ký**. Máy thật chạy trình duyệt, bộ điều phối và Qwen3 8B. VM host-only chứa mẫu và các công cụ phân tích tĩnh. Qwen chọn hành động từ danh sách cho phép và nhận các đoạn đặc trưng đã lọc. VM trả về mã chứng cứ, tọa độ và hash.
3. Khi có báo cáo, vào **Bản đồ chứng cứ**, chọn **Tuần tự hóa thông điệp → Gọi API gửi**. Phần **Các lần agent kiểm tra liên kết** cho biết truy vấn nào đã trả về dòng còn thiếu. Bấm **Mở … trong báo cáo** để tới nhận định trích cùng vị trí. Mỗi nút dựa trên cả mã chứng cứ và khoảng dòng.
4. Trong **Nhận định**, mở câu gắn nhãn **Đối chiếu đường truyền** rồi bấm **Xem đoạn mã đã dẫn**. Ở lượt Python dưới đây, C31 dẫn đường từ đối số tệp tới nội dung MIME. C32 dẫn tiếp tới đối số gửi thư. Câu hỏi còn mở là nội dung đính kèm có thực sự xuất phát từ dữ liệu nhạy cảm đã đọc hay không.
5. Vào **Đánh giá → Đường truyền trong báo cáo · đối chứng trên ba mẫu** để xem các chỉ số phát triển. **Hỏi đáp** có thể mở lại bằng chứng hoặc yêu cầu VM tìm tiếp. **YARA** chạy phép thử luật thật và **Gán nhãn** lưu nhận xét sau khi người dùng kiểm tra nguồn. Bấm **Tắt lab** khi kết thúc để giải phóng RAM/VRAM. [Luồng hỏi đáp, YARA và gán nhãn](WEB_DIEU_TRA.md)

## Cách dựng một nhận định

- Vòng ReAct cập nhật trạng thái từng liên kết sau khi VM trả kết quả. Bản đồ có ba trạng thái **Có bằng chứng**, **Cần kiểm tra thêm**, **Chưa tìm thấy**. Khi hết ngân sách tìm, liên kết còn thiếu giữ nguyên trạng thái.
- Bước lập báo cáo lấy chứng cứ đã truy xuất. Với Python, nó kiểm các điểm mở tham số tệp, đọc byte, gắn phần MIME và tuần tự hóa. Chỉ ghép thêm lời gọi gửi nếu cùng nguồn và đúng vị trí tuần tự hóa. Với .NET, nó kiểm kiểu đối tượng, phép gán tiền tố đường dẫn và đối số thực tế ở lời gọi tải tệp. Mỗi nhận định chỉ mô tả đoạn được trích.
- Qwen đọc từng đề xuất và trích dẫn trước khi lập verdict. Nhật ký chứa đề xuất, các lượt model, quyết định giữ/loại và kết luận cuối. Bộ chấm dùng đáp án đã chốt để kiểm lại độc lập với câu trả lời của Qwen. Nhãn thực nghiệm hiện do dự án đối chiếu nguồn, chưa có người chấm mù bên ngoài.

## So sánh trên cùng dữ liệu

Ba hồ sơ phát triển gồm PythonStealer, Gomorrah và Mercurial, có tổng cộng 97 mục tham chiếu. Nhánh gốc tái lập đúng yêu cầu suy luận, danh sách nhận định và verdict đã lưu. Ở nhánh mới, Qwen thực hiện thêm bốn lượt duyệt và ba lượt tổng hợp verdict thật với chính dữ liệu VM đã lưu. Phép so này đo tác động của việc đưa liên kết vào báo cáo. Chi phí tìm kiếm và dịch ngược ban đầu bằng nhau ở hai nhánh. [Biên bản theo mẫu, số token và thời gian từng lượt](../deliverables/real-demo-evidence/transfer-report-comparison.json)

| Chỉ số | Báo cáo gốc | Thêm đối chiếu | Mục tiêu slide |
|---|---:|---:|---:|
| Mục đúng / mục tham chiếu | 35/97 | 37/97 | — |
| Precision | 89,74% | 90,24% | ≥80% |
| Recall | 36,08% | 38,14% | ≥70% |
| F1 tổng hợp | 51,47% | 53,62% | ≥75% |
| F1 riêng IOC và ATT&CK | 42,86% | 53,33% | ≥80% ở mức xuất sắc |
| Câu thiếu căn cứ / câu giữ | 4/69 (5,80%) | 4/73 (5,48%) | ≤5% |
| Câu có trích dẫn / câu giữ | 69/69 | 73/73 | ≥90% |
| Verdict đúng theo nhãn độc | 0/3 | 0/3 | 100% |

Cả bốn câu mới đều có nguồn hỗ trợ. Hai câu làm tăng recall. Python bổ sung thao tác đưa byte tệp vào nội dung MIME ở dòng 96–98. Gomorrah bổ sung tiền tố đường dẫn tương đối ở dòng 3677 được dùng tại dòng 3681. Một tiền tố khác ở dòng 3599–3603 có thật nhưng đáp án khóa lần xuất hiện ở 3573 và 3577. Câu Python về đối số gửi thư cũng có giá trị điều tra nhưng không thêm mục tham chiếu. Mercurial không sinh đề xuất mới. Cả ba verdict vẫn là `suspicious`.

**Giới hạn khi đọc điểm.** 73/73 câu có trích dẫn và chỉ 68/73 câu được nội dung nguồn hỗ trợ đầy đủ. Các kết quả trên thuộc tập phát triển. Thí nghiệm khác dùng truy vấn cố định hoặc thích nghi để *lấy thêm dòng trong VM* và phát sinh những nhận định khác. [Điểm riêng của ba cách truy vấn](PHU_LUC_DIEU_TRA_NET.md)

## Lượt chạy lại từ trình duyệt

**PythonStealer** · `20261128T053257_fbd5c41a` · 434,27 giây · 17 lần gọi công cụ, một lần lỗi · 40 lần gọi Qwen. Bốn công cụ trả kết quả thành công. Báo cáo giữ 31 câu, YARA khớp trong tập phát triển. Hai câu mới có bảy trích dẫn mở được trên web, đã đối chiếu với hash và tọa độ nguồn. Cả 30 đề xuất cũ trùng văn bản và trích dẫn của lượt gốc. Bộ duyệt thay hai quyết định. Lượt này đạt 21/36 mục, precision 95,45%, recall 58,33%, F1 72,41%. [Nhật ký rút gọn](../deliverables/real-demo-evidence/web-20261128T053257_fbd5c41a.json) · [Phiếu đối chiếu các lần bấm và điểm số](../deliverables/real-demo-evidence/transfer-live-20261128T053257_fbd5c41a.json)

**Gomorrah (.NET)** · `20261128T065309_3102f839` · 577,42 giây · 17 lần gọi công cụ thành công · 52 lần gọi Qwen. Agent giữ 26 câu và YARA khớp trong tập phát triển. Trên web, C29 và C30 mở được cả bốn trích dẫn về hai tiền tố. Riêng lần chạy mới này, agent lấy được cặp dòng 3573 và 3577 theo đúng đáp án, ngoài cặp 3677 và 3681. Verdict vẫn là `suspicious`. Chấm theo 40 mục cố định được 13 đúng, 27 bỏ sót, một ý sai và hai ý thiếu căn cứ. Precision 81,25%, recall 32,50%, F1 46,43%. Có 18/26 câu trùng nội dung và trích dẫn đã chấm khi chuẩn hóa mã lượt/câu. Tám câu còn lại có phiếu chấm riêng. Ví dụ, C13 nhận diện đúng lời gọi ở dòng 4099 nhưng diễn giải sai tên của giá trị enum bằng 0. [Biên bản chạy thật](../deliverables/real-demo-evidence/web-20261128T065309_3102f839.json) · [Phiếu chấm tám câu](../eval/adjudications/transfer-live-20261128T065309_3102f839.json) · [Điểm và trích dẫn đã mở](../deliverables/real-demo-evidence/transfer-live-20261128T065309_3102f839.json)

Hai lượt bấm mới trên là kết quả đầu-cuối riêng từng mẫu. Phép đối chứng 37/97 ở trên giữ cố định cả ba hồ sơ gốc.

## Tính lại điểm

Trong môi trường Python của dự án, lệnh thứ nhất dùng bằng chứng công khai trong Git. Các lệnh sau đối chiếu riêng với các nhật ký trên máy lab.

```powershell
python -m eval.transfer_report_audit
python -m eval.transfer_report_audit --replay
python -m eval.transfer_live_audit 20261128T053257_fbd5c41a
python -m eval.transfer_live_audit 20261128T065309_3102f839
```

Để làm một thí nghiệm mới trên chính ba hồ sơ gốc, bật lab rồi chạy `python -m eval.transfer_report_trial`. Mỗi lần chạy có thư mục riêng. Bộ chấm giữ mã thí nghiệm đã đo để lần chạy mới có thể được chấm riêng. Bản đối chiếu sau lần đầu thu hẹp cú pháp .NET xuống một lời gọi rõ đối số trên một dòng. Việc phát lại trên ba hồ sơ khớp từng thông điệp gửi Qwen và từng verdict của thí nghiệm đã ghi.
