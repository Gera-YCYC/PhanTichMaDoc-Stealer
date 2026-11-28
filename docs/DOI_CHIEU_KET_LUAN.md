# Kiểm tra verdict và các lượt điều tra bị ngắt

## Đối chiếu hai báo cáo và một lượt bị ngắt

Ba lượt liên tiếp trên PythonStealer 2024 dùng cùng SHA-256 mẫu, Qwen3 8B, cấu hình và mã lõi. Agent yêu cầu VM đọc tĩnh, sau đó model tổng hợp và tự duyệt từng câu. Bảng ghi cả lượt kết thúc trước bước chốt báo cáo.

| Lượt | Công việc hoàn tất | Đúng / Sai / Bịa / Bỏ sót | Precision | Recall | F1 | Verdict |
|---|---|---|---:|---:|---:|---|
| `20261128T085636_4eaac445` | Báo cáo và bản đồ | 21 / 0 / 0 / 15 | 100% | 58,33% | 73,68% | suspicious |
| `20261128T091615_0ffb665e` | Báo cáo và bản đồ | 21 / 1 / 0 / 15 | 95,45% | 58,33% | 72,41% | suspicious |
| `20261128T092538_136e21fd` | Bản đồ tĩnh, dừng khi duyệt thao tác | Chưa có báo cáo để chấm | — | — | — | Chưa chốt |

Hai báo cáo đã chốt cùng tìm được 21 trong 36 mục tham chiếu. Giữa chúng có 32/38 nhận định trùng nhau theo khóa của phép đo (84,21%). Lượt thứ ba dừng sau 345,7 giây với 17 lần gọi công cụ, 34 lần gọi model và một lỗi công cụ. Tại lần đo thấp nhất, máy còn 201.920.512 byte RAM trống (192,6 MiB), dưới ngưỡng 256 MiB. Nhật ký ghi nhận agent giải phóng model. Ở thời điểm dừng, bản đồ đã có 4/7 đường nối được công cụ hỗ trợ. Độ ổn định theo yêu cầu **ba báo cáo** vẫn chưa đo được ở cấu hình này. Đợt ba báo cáo ở phiên bản trước đạt 28/40 (70%). [Đợt đo trước](DO_ON_DINH_BAN_DIEU_TRA.md) · [Dữ liệu ba lượt](../deliverables/real-demo-evidence/argument-stability.json)

Nhãn của mẫu phát triển là độc. Cả hai verdict `suspicious` đều trượt tiêu chí kết luận lành/độc. Ngưỡng giảng viên cho precision, recall và F1 lần lượt là 80%, 70% và 75%. Một nhận định lấy đủ dòng trích dẫn vẫn có thể diễn giải sai quan hệ giữa các hàm. Cần mở đoạn nguồn trước khi chấm nhãn ngữ nghĩa.

## Vì sao Qwen kết luận như vậy?

Trong **Nhận định → Vì sao báo cáo đưa ra verdict này?**, nhóm xem đề xuất gốc, verdict được ghi, các câu làm bằng chứng cho thu thập, gửi đi và liên kết dữ liệu. Bấm mã câu để đọc trích dẫn. Khi một câu được chọn cho một vai trò nhưng không nằm trong danh sách dẫn hợp lệ, web đánh dấu cho người đọc kiểm lại. Với lượt Python đầu, chính Qwen đã đề xuất `suspicious`.

Để thử giảm lỗi tham chiếu, mỗi lượt của thí nghiệm nhận đúng các câu hành vi đã giữ trong một hồ sơ. Qwen chọn tối đa ba ID cho từng vai trò. Chương trình hợp nhất các ID đã chọn. Ba lần suy luận dùng model thật. Trước khi chạy, nhóm chốt 15 trường hợp đối chiếu theo nội dung, vị trí và hash câu. Mỗi mẫu có hai ví dụ hỗ trợ và ba ví dụ không hỗ trợ vai trò. [Bộ đối chiếu](../eval/adjudications/verdict-role-controls.json) · [Kết quả suy luận](../deliverables/real-demo-evidence/verdict-role-trial.json)

| Chỉ số trên cùng ba hồ sơ | Cách cũ | Cách chọn ID theo vai trò |
|---|---:|---:|
| Verdict khớp nhãn mẫu | 0/3 | 2/3 |
| Nhóm vai trò chứa tham chiếu ngoài danh sách dẫn hợp lệ | 5 | 0 |
| Ví dụ hỗ trợ được chọn | 5/6 | 3/6 |
| Ví dụ không hỗ trợ bị chọn | 3/9 | 1/9 |

Gomorrah vẫn có một câu được chọn nhầm cho vai trò. Với Mercurial, Qwen đề xuất `malicious` trong phép thử nhưng để hai vai trò trống, nên chương trình ghi `suspicious`. Cả ba hồ sơ đều là mẫu độc thuộc tập phát triển. Bảng này chưa đo tỷ lệ kết luận nhầm trên file lành. Cách mới chỉ xuất hiện trong **Đánh giá**. Khi không có trích dẫn nối đúng dữ liệu thu thập với nơi gửi, nhóm vẫn cần kiểm chứng liên kết trên bản đồ.

## Ba mẫu đã chốt trước khi chạy .NET

Lượt Python bị ngắt đã được chọn cùng hai lượt .NET tiếp theo, theo thứ tự Gomorrah và Mercurial. Mỗi lượt khớp hash của mẫu đã chọn. Cả ba dùng cùng phiên bản mã lõi, cấu hình và model đã khóa trong biên bản. Hai báo cáo .NET đã có điểm. Gomorrah đúng 12/40 mục, precision 80%, recall 30%, F1 43,64%. Mercurial đúng 5/21 mục, precision 83,33%, recall 23,81%, F1 37,04%. Cả hai ghi `suspicious` trên mẫu mang nhãn độc. Trên hai báo cáo chấm được, tổng cộng đúng 17/61 mục, bỏ sót 44, có bốn mệnh đề thiếu căn cứ, F1 gộp 41,46%. Cả bộ thử có 97 mục, trong đó 36 mục thuộc lượt Python bị ngắt. [Thứ tự đã chốt](../eval/adjudications/argument-three-sample-protocol.json) · [Bảng điểm cả đợt](../deliverables/real-demo-evidence/argument-cross-format.json)

Trong lượt Mercurial, người xem đã bấm **Hỏi tiếp về đường nối này** từ quan hệ đọc kết quả truy vấn → xử lý. Agent gọi lại công cụ trong VM. Công cụ trả bảy vị trí khớp, hai vị trí được trích ở dòng 728 và 796. Trình duyệt đã mở và kiểm hash trích đoạn đầu. Đây là hai điểm đọc bảng. Muốn xác nhận luồng đến nơi xử lý vẫn cần bằng chứng về cùng giá trị đi vào lời gọi tiếp theo. [Biên bản câu hỏi của lượt Mercurial](../deliverables/real-demo-evidence/web-20261128T094444_607b0b2d.json)

## Thao tác trình diễn

1. Từ PowerShell ở thư mục đồ án trên máy đã cài lab, chạy `.\scripts\Start-Web.ps1`. Mở trình duyệt ở địa chỉ `http://127.0.0.1:4180`. Chờ hai trạng thái Ollama và VM sẵn sàng rồi chọn mẫu và bấm **Chạy điều tra**.
2. Trong **Đánh giá → Ba lượt cùng phiên bản kiểm tra đối số**, mở từng mục đáp án hoặc xem danh sách câu thay đổi. Bấm mã câu để về đúng báo cáo. Bấm mã lượt bị ngắt để xem nhật ký trên máy giữ hồ sơ. Các bảng trên máy vừa clone dùng số liệu đã công bố. Trích đoạn riêng của một lượt cần có nhật ký tương ứng trên máy đó.
3. Trong **Bản đồ chứng cứ**, mở một đường nối được xác minh và đọc các vị trí nguồn, sau đó mở một đường còn thiếu. Trong **Hỏi đáp**, yêu cầu agent giải thích phần thiếu. Trong **YARA**, xem các lần thử luật trên mẫu và file sạch. Khi hết demo, chờ tác vụ kết thúc và bấm **Tắt lab**.
4. Để tính lại số liệu từ bản Git bằng Python của dự án, chạy các lệnh bên dưới. Tùy chọn `--replay` của `eval.report_series` kiểm thêm nhật ký riêng trên máy lab.

```powershell
.\.venv\Scripts\python.exe -m eval.cross_format
.\.venv\Scripts\python.exe -m eval.report_series --argument
.\.venv\Scripts\python.exe -m eval.verdict_trial --portable
```
