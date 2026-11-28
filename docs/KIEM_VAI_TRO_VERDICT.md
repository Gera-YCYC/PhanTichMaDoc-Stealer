# Kiểm từng nguồn trước khi dùng một câu để kết luận

Một câu có thể mô tả đúng thao tác sao chép tệp nhưng vẫn bị dùng sai để chứng minh truyền dữ liệu. Từ bản báo cáo `evidence-cards/15`, mỗi cặp **nhận định và vai trò do Qwen đề xuất** có một quyết định riêng. Hai nhận định trích cùng một khoảng dòng vẫn có thể nhận hai quyết định khác nhau.

## Chạy và mở chứng cứ trên web

1. Trên Windows đã dựng lab, chạy `.\scripts\Start-Web.ps1`, mở `http://127.0.0.1:4180`, chọn Mercurial rồi bấm **Chạy điều tra**. Cổng kết nối model, kiểm tra cô lập VM và nhật ký thao tác nằm trong cùng lượt.
2. Sau khi có báo cáo, mở **Nhận định → Vì sao báo cáo đưa ra verdict này?**. Mở một hàng theo mã câu, xem quyết định và bấm **Xem đoạn mã đã dẫn** ở từng vị trí Qwen chọn. **Đọc nhận định C…** đưa về nguyên câu. Những dòng mô tả đối số lỗi vẫn có thể đọc ở bản đồ.
3. Dưới vai trò liên hệ dữ liệu với nơi gửi, bấm **Kiểm tra trên bản đồ** để truy tiếp mắt xích còn thiếu. Khi tác vụ hoàn tất, bấm **Tắt lab**. Thành viên mới có thể dựng lab và thử trên máy mình theo hướng dẫn. [Cài đặt](TEAM_SETUP.md)

## Điều kiện xét một vai trò

| Vai trò được đề xuất | Chứng cứ cần cho chính câu đang xét |
|---|---|
| Thu thập dữ liệu nhạy cảm | Dòng nhận diện nguồn dữ liệu và dòng thực hiện đọc hoặc sao chép. Một dòng có thể chứa đủ hai chi tiết. |
| Gọi thao tác gửi | Điểm gọi mạng đã được bộ phân tích ràng buộc và nhận định mô tả chính thao tác đó. Bản hiện tại nhận dạng SMTP send và .NET WebClient.UploadFile. Những API khác có thể cần bổ sung công cụ. |
| Liên hệ dữ liệu thu thập với thao tác gửi | Nguồn nhạy cảm, dòng ràng buộc dữ liệu với đối số gửi và điểm gọi mạng trong cùng đầu ra đã kiểm mã băm. Qwen còn phải xác nhận câu mô tả đúng quan hệ. |

Agent kiểm mã mẫu, mã đầu ra, phạm vi và nội dung của trích dẫn trước khi cho chọn số dòng. Nếu thiếu điểm gọi gửi đã xác minh, bộ điều khiển ghi lý do ngay. Khi còn chứng cứ phù hợp, Qwen đọc câu và các dòng, trả về lựa chọn cho từng phần hoặc bỏ trống. Quyết định sau cùng vẫn là một đánh giá của model về mã tĩnh. Trên một luồng có biến bị gán lại, nhiều nhánh hoặc đi qua nhiều hàm, người đọc cần kiểm tiếp. [Bộ kiểm](../stealer_agent/role_evidence.py) · [Điểm tích hợp vào báo cáo](../stealer_agent/evidence_cards.py)

## Cách đánh giá

Nhóm khóa mã bộ kiểm, cấu hình, digest Qwen và 19 cặp câu–vai trò trước khi chạy. Có 15 cặp từ ba báo cáo phát triển đã chấm trước và bốn cặp chẩn đoán từ lượt Mercurial kế tiếp. Các nhãn được đối chiếu với nguồn. Hai lượt Mercurial dùng cùng tệp. Nhãn và lý do chấm nằm ngoài đầu vào gửi cho Qwen. [Tiêu chí và mã băm](../eval/adjudications/role-lines-protocol.json) · [15 cặp đã có từ trước](../eval/adjudications/verdict-role-controls.json)

- **Đề xuất ban đầu** đếm các cặp Qwen đã chọn và đã dẫn trong verdict cũ.
- **Sau kiểm nguồn** chỉ tính cặp trong nhóm trên còn đủ chứng cứ. Cách sàng lọc có thể bỏ nhầm một cặp đúng và không tự tìm lại cặp đã vắng khỏi đề xuất.
- **Xét tất cả cặp** đo bộ kiểm trên từng câu–vai trò kể cả khi Qwen chưa đưa câu vào verdict. Đây là phép đo chẩn đoán, có thể chạy lại từ nhật ký mà không sửa báo cáo gốc.

Các cặp hiện có ví dụ dương cho thu thập và thao tác gửi. Với vai trò nối dữ liệu đến bên gửi, bộ thử này mới có ví dụ âm. Cần thêm ca dương độc lập để đo khả năng nhận đúng một đường truyền đầy đủ. Điểm ở cấp vai trò và điểm của toàn báo cáo có mẫu số riêng.

Từ repo đã cài Python, lệnh dưới đây tính lại các bảng từ biên bản đã công bố. Máy giữ nhật ký gốc có thể thêm `--replay` để đối chiếu từng yêu cầu, phản hồi của Qwen và tọa độ từ VM.

```powershell
.\.venv\Scripts\python.exe -m eval.role_line_study
```

## Kết quả 19 cặp đã chốt

| Cách chọn | Giữ đúng trong 7 cặp dương | Giữ sai trong 12 cặp âm | Bỏ sót cặp đúng | Loại đúng cặp âm |
|---|---:|---:|---:|---:|
| Đề xuất Qwen có dẫn trong verdict gốc | 3 | 4 | 4 | 8 |
| Sau kiểm dòng nguồn | 2 | 1 | 5 | 11 |
| Yêu cầu xét riêng tất cả 19 cặp | 4 | 3 | 3 | 9 |

Ba cặp giữ sai được loại đều thuộc lượt Mercurial dùng để chẩn đoán lỗi C11/C12. Trên 15 cặp có từ trước, bước sàng lọc giữ nguyên các lựa chọn của verdict. Khi gộp 19 cặp, precision của lựa chọn tăng từ 3/7 lên 2/3, recall giảm từ 3/7 xuống 2/7. Có 12 lần gọi model, tổng thời gian suy luận 44,03 giây cho phép xét riêng. Một số cặp dừng ngay khi công cụ thiếu điểm gửi. [Mọi quyết định và chi phí từng cặp](../deliverables/real-demo-evidence/role-line-study.json)

**Kiểm tiếp các dòng được chọn.** Trong phép xét riêng, Qwen duyệt 7 cặp. Bốn cặp đúng về vai trò, nhưng chỉ **2/7** có bộ dòng được chọn đủ chứng minh chính câu đó. Ví dụ, một câu trên Python mô tả tạo bản nén, song khoảng trích rộng chứa cả lời gọi SMTP nên Qwen chọn nhầm dòng gửi. Trên Gomorrah, Qwen dùng riêng dòng 3655 cho cả nguồn nhạy cảm, bước ràng buộc và thao tác gửi. Trên Mercurial, có câu mô tả đúng việc sao chép nhưng hai dòng được chọn là chú thích và phép tạo đường dẫn. Trong **Đánh giá**, chọn từng mẫu và mở **Kiểm lại từng vai trò bằng dòng nguồn → Dòng đã chọn đủ chứng minh**. [Đối chiếu hậu nghiệm toàn bộ bảy cặp](../eval/adjudications/role-lines-witness-audit.json)

**Mở lại một điểm gửi bị bỏ qua.** Dưới vai trò gửi ở tab **Nhận định**, mục **Điểm gọi gửi có trong báo cáo nhưng chưa làm căn cứ** tìm những câu đã được giữ có nguyên văn và mọi trích dẫn khớp thao tác gửi do VM ràng buộc. Trên Python, có thể mở C22 ở dòng 109. Trên Gomorrah có năm vị trí, gồm C25 ở dòng 3577. Hai cặp C22/C25 thuộc ba cặp dương về gửi mà verdict ban đầu bỏ qua. Đây là gợi ý đối chiếu hiển thị sau khi phân tích. Điểm và verdict gốc nằm trong nhật ký riêng. Đã mở từng điểm và quay về nguyên câu trên giao diện 390 và 1360 px. [Biên bản thao tác sáu vị trí](../deliverables/real-demo-evidence/role-unused-sends-browser.json)

## Lượt trực tiếp qua web

Lượt `20261128T121940_ea602383` là lần điều tra Mercurial đầu tiên sau khi khóa quy trình. Qwen3 8B trên máy thật và VM cô lập hoàn tất sau **567,31 giây**, 17 lần gọi công cụ, 0 lỗi công cụ và 54 lần gọi model. Bước kiểm vai trò xử lý 11 cặp do Qwen đề xuất. Sáu cặp thiếu ID trong danh sách nguồn cho verdict, hai cặp thiếu điểm gửi đã xác minh và ba cặp thu thập được đưa lại cho model đọc. Ba lần đọc mất 12,24 giây và đều trả về chưa đủ. Có thao tác sao chép kho dữ liệu trình duyệt thực sự xuất hiện trong báo cáo, nên việc bỏ trống toàn bộ vai trò thu thập là một thiếu sót. [Đủ đề xuất, quyết định và thời gian](../deliverables/real-demo-evidence/role-lines-live.json)

| Báo cáo Mercurial | Đúng / sai / bịa / bỏ sót theo ý | Precision | Recall | F1 | Verdict |
|---|---|---:|---:|---:|---|
| Lượt liền trước, theo bảng đã khóa | 7 / 1 / 1 / 14 | 77,78% | 33,33% | 46,67% | suspicious |
| Lượt kiểm từng vai trò | 9 / 1 / 0 / 12 | 90,00% | 42,86% | 58,06% | suspicious |

Trong 23 câu được giữ ở lượt mới, 22 câu đúng, một câu sai và cả 23 có trích dẫn. Câu mô tả một giá trị được đưa vào bước thử giải mã chưa xác định vai trò mật khẩu của giá trị, nên không được điểm cho mục đó. Bước kiểm vai trò chạy sau khi agent đã chọn và viết câu. Chênh lệch F1 giữa hai lượt độc lập bao gồm khác biệt của các câu được sinh trước bước kiểm. Mốc tham chiếu là F1 ít nhất 75% và verdict đúng trên toàn bộ mẫu lab. [Nhãn năm câu mới](../eval/adjudications/transfer-live-20261128T121940_ea602383.json) · [Điểm, hash và các câu được kế thừa](../deliverables/real-demo-evidence/transfer-live-20261128T121940_ea602383.json) · [Lượt web và thao tác ở hai cỡ màn hình](../deliverables/real-demo-evidence/web-20261128T121940_ea602383.json)
