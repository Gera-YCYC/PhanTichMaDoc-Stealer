# Khi mã đọc cột số, agent biết được gì?

Trên mẫu Mercurial, ILSpy cho thấy chương trình chọn một bảng và đọc ba vị trí bằng số. Một báo cáo cũ đi xa hơn và gán tên cho cả ba vị trí. Bài thử này kiểm hai câu hỏi khác nhau. Khi giữ nguyên câu và đoạn nguồn, bộ duyệt có phát hiện phần suy diễn không? Khi chạy lại toàn bộ agent, báo cáo cuối có tìm được nhiều mục trong đáp án hơn không?

## Trình diễn trên web cục bộ

1. Mở PowerShell tại thư mục dự án trên máy Windows đã dựng lab. Chạy `.\scripts\Start-Web.ps1` và mở `http://127.0.0.1:4180`. Kiểm tra trạng thái kết nối Ollama và VM. [Chuẩn bị máy thành viên](TEAM_SETUP.md)
2. Chọn **public_mercurial.bin → Chạy điều tra**. Trong **Nhật ký**, xem lần agent điều tra một quan hệ còn thiếu. Khi hoàn tất, ghi mã lượt và verdict. Có thể dùng thanh **Lịch sử** để đối chiếu một lượt đã chạy trên máy này.
3. Mở **Bản đồ chứng cứ → Đọc kết quả truy vấn**. Bấm vào một dòng dùng chỉ số. Đọc các trích dẫn về biến đọc, thao tác chọn bảng và đối số ở điểm gọi. Nếu một câu trong báo cáo dẫn đủ các vị trí này, nút bên cạnh mở câu được giữ hoặc bị loại.
4. Bấm **Tìm lược đồ trong VM → Tra cứu chứng cứ**. Qwen chọn một phép tìm chuỗi chỉ đọc trong bản dịch ngược của đúng mẫu và lần chạy. Màn hình ghi câu hỏi, số lần khớp và tọa độ có thể mở. Nếu tìm thấy mô tả bảng, vẫn phải xác minh bảng, phiên bản và thứ tự cột trước khi đặt tên. Nếu VM vừa khởi động lại, chạy một lượt mới để có mã chứng cứ hiện hành.
5. Mở **Đánh giá → Mercurial → Kiểm tra câu gán tên cho cột số**. Bấm **Xem C2** để đối chiếu câu gốc. Bấm mã lượt mới để kiểm các vị trí trên bản đồ. Dữ liệu dùng chấm và bảng điểm có trong Git. Các đoạn mã hiển thị cần nhật ký trên máy đã phân tích. Kết thúc bằng **Tắt lab**.

## Cách chấm

Phép thử ghép cặp giữ nguyên tám câu của bốn nhóm trích dẫn có thao tác đọc theo chỉ số. Nhãn yêu cầu tất cả các ý trong một câu đều được nguồn hỗ trợ. Qwen duyệt lại đúng tám yêu cầu với chỉ dẫn và cấu trúc phản hồi mới. Các lựa chọn dựa trên kết quả thực, gồm cả câu đúng bị loại. [Kế hoạch thí nghiệm](../eval/adjudications/ordinal-review-protocol.json) · [Nhãn và dòng kiểm chứng](../eval/adjudications/ordinal-review-claims.json)

Phép thử đầu–cuối lấy lượt web kế tiếp của cùng mẫu, cùng model và cấu hình. Chấm riêng độ phủ trên 21 mục tham chiếu và chất lượng từng câu xuất hiện trong báo cáo. Một câu có ý thiếu căn cứ được xếp vào nhóm thiếu căn cứ. Khi các ý đều có căn cứ nhưng có ý diễn giải sai, xếp vào nhóm sai. Tỷ lệ có trích dẫn cho biết người đọc có thể tìm về nguồn. Việc nguồn có chứng minh toàn bộ câu hay không cần kết quả chấm ngữ nghĩa. Các nhãn hiện thuộc tập phát triển, còn chờ người chấm độc lập.

## Kết quả trên Mercurial

| Cùng tám câu và cùng nguồn | Giữ câu đủ căn cứ | Giữ câu thiếu căn cứ hoặc sai | Loại câu đủ căn cứ |
|---|---:|---:|---:|
| Bộ duyệt cũ | 4/5 | 1/3 | 1/5 |
| Bộ duyệt có kiểm chỉ số | 4/5 | 0/3 | 1/5 |

C2 của lượt gốc gán tên cho ba chỉ số. Bộ duyệt mới loại câu này và giữ lại C1 về thao tác sao chép, mở bản sao và chọn bảng. Một tổn thất là C9 bị loại dù hai thao tác đọc theo chỉ số có trong nguồn. Trên tám câu, số quyết định phù hợp với nhãn tăng từ 6 lên 7. Phạm vi phép thử ghép cặp chỉ gồm một mẫu và tám câu đã khóa. [Kết quả từng câu](../deliverables/real-demo-evidence/ordinal-review-study.json)

| Hai lần điều tra trọn vẹn | Mục đúng / 21 | Sai / thiếu căn cứ / bỏ sót theo mục | Precision | Recall | F1 | Verdict | Công cụ / giây |
|---|---:|---:|---:|---:|---:|---|---:|
| `20261128T110548_0cb9678e` | 4 | 1 / 3 / 17 | 50,00% | 19,05% | 27,59% | suspicious | 17 / 677,7 |
| `20261128T112458_a0bfcbd3` | 7 | 1 / 3 / 14 | 63,64% | 33,33% | 43,75% | suspicious | 17 / 636,6 |

Khi chấm *toàn câu*, lượt trước có 20 câu đúng, 1 sai và 1 thiếu căn cứ trong 22 câu. Lượt mới có 16 câu đúng, 1 sai và 3 thiếu căn cứ trong 20 câu. Tỷ lệ thiếu căn cứ tăng từ 4,55% lên 15%, trong khi cả hai báo cáo đều dẫn nguồn ở 100% câu. Các lỗi mới gồm diễn giải tác dụng của helper từ nơi gọi, suy thứ tự cột từ đối số số và khẳng định dữ liệu đã được gửi từ một lời gọi truyền đường dẫn. Hai lượt sinh báo cáo riêng, nên chưa thể quy mức tăng F1 cho riêng bộ kiểm cột. [Bảng chấm](../deliverables/real-demo-evidence/transfer-live-20261128T112458_a0bfcbd3.json) · [Lý do chấm các câu mới](../eval/adjudications/transfer-live-20261128T112458_a0bfcbd3.json)

Trong lượt mới, Qwen3 8B được gọi 50 lần. VM thực hiện 17 lần gọi công cụ, gồm nhận dạng PE, dịch ngược bằng ILSpy và tìm/đọc chứng cứ. Nhật ký ghi 0 lỗi công cụ. Sau khi báo cáo hoàn tất, từ vị trí 739 trên bản đồ, người dùng yêu cầu tìm thêm lược đồ. Qwen chọn `sqlite_master`. VM trả 0 kết quả trong bản dịch ngược. Giao diện giữ tên cột ở trạng thái chưa xác minh và mở được ba trích dẫn ban đầu tại các dòng 727, 728, 739. Câu hỏi có nhật ký riêng `q_6e735fc9227e`. Phép thử trình duyệt trên hai chiều rộng 390 và 1360 pixel mở được tám quyết định trên bản đồ cùng các dòng của C2 gốc. [Biên bản lượt chạy và tương tác](../deliverables/real-demo-evidence/web-20261128T112458_a0bfcbd3.json)

## Tái kiểm

Từ thư mục gốc sau khi cài môi trường Python, chạy lệnh sau để đọc lại kết quả công khai. Trên máy còn nhật ký riêng của đợt đo, thêm `--replay` để đối chiếu với yêu cầu gửi model, kết quả VM và bảng chấm. Mỗi lần chạy điều tra trực tiếp qua web tạo một mã lượt mới.

```powershell
.\.venv\Scripts\python.exe -m eval.ordinal_review_study
```

Để nghiệm thu, nhóm phải cải thiện recall, F1, verdict và tỷ lệ thiếu căn cứ trên cùng phiên bản. Thử tiếp trên cả mẫu độc và mẫu lành đã tách khỏi phát triển, chấm độc lập và đo độ ổn định ba lượt. [Tiêu chí của môn](PROJECT_GOAL.md) · [Phân công phần còn lại](CONG_VIEC_CON_LAI.md)
