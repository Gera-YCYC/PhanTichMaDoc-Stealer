# Lời gọi .NET nào có chứng cứ trong thân hàm?

Một lời gọi truyền đường dẫn cho hàm phụ đặt ra hai câu hỏi khác nhau. Hàm phụ có đọc nội dung tệp không? Chính phần mã đang xem có thao tác gửi yêu cầu HTTP không? Phụ lục web cho phép kiểm tra hai câu hỏi trên cùng bản dịch ngược, kể cả khi agent phải trả lời “chưa có dẫn chứng”.

## Demo trên máy lab

1. Mở PowerShell ở thư mục gốc và chạy `.\scripts\Start-Web.ps1`. Vào `http://127.0.0.1:4180`. Trên máy thành viên mới, dựng VM và chuẩn bị model theo [hướng dẫn cài đặt](TEAM_SETUP.md).
2. Chọn hồ sơ Mercurial `20261128T031606_ca91de35` trong lịch sử của máy đã demo. Trên máy mới, chạy điều tra Mercurial rồi mở hồ sơ vừa tạo. Các dòng dưới đây áp dụng cho đúng hash nguồn trong biên bản.
3. Chọn **Nhận định → Điều tra bổ sung trên mã .NET**. Nếu hồ sơ chưa có phụ lục, bấm **Tìm thêm và lập phụ lục**. Mở **Đối chiếu lời gọi với thân hàm**.
4. Để **Để agent chọn lời gọi**, bấm **Kiểm tra trong VM**. Trong lượt đo, Qwen chọn dòng 261. Mở kết quả, so hai câu trả lời trước/sau và mở các dòng VM đã trả. Có thể chọn riêng dòng 245 hoặc 244 để kiểm tra một giả thuyết khác.
5. Mở **Bản đồ chứng cứ → Các lời gọi .NET đã đối chiếu trong phụ lục**. Bấm vào dòng 245 để mở dòng được dẫn cho thao tác đọc tệp. Các tọa độ này là đầu mối khi điều tra quan hệ giữa các thao tác. Việc tô trạng thái xác nhận một đường nối vẫn đòi hỏi chứng cứ về chính dữ liệu đi qua nó.
6. Có thể tải lại trang và mở lại hồ sơ. Sáu lượt đối chiếu hoàn tất gần nhất của phụ lục hiện tại hiện ở mục Nhận định. Kết thúc demo bằng nút **Tắt lab**.

## Từ câu hỏi đến trích dẫn

Qwen chọn từ các lời gọi xuất hiện trong những dòng người dùng mở được. Trình điều phối gửi mã mẫu đến VM. ILSpy dịch ngược lại mẫu và hệ thống đối chiếu SHA-256 mẫu, đầu ra và digest model với hồ sơ. Công cụ đọc chỉ nhận mã bằng chứng và số dòng. Bộ phân tích cú pháp trong VM tìm khai báo trường có kiểu tường minh, kiểu được khởi tạo, lớp cùng phạm vi và một phương thức phù hợp số đối số. Dòng có biến che khuất tên trường, tên hàm nạp chồng, phương thức ảo hoặc phần trích vượt ngân sách có thể trả về chưa xác định. Chế độ tự chọn thử tối đa ba dòng khác nhau. Mỗi lần chọn sau nhận kết quả lần trước.

Phần trả về giới hạn 40 dòng và 4.700 ký tự mã. Host lọc chỉ dẫn chèn và che literal trước khi hỏi model. Dòng khai báo trường có giá trị riêng tư chỉ còn tọa độ trên giao diện. Qwen trả lời hai lần với cùng câu hỏi, lần đầu chỉ thấy nơi gọi, lần sau thấy thêm phần mã truy được. Mỗi câu trả lời chọn số dòng trong tập cho phép hoặc trả 0 khi thiếu căn cứ. Bộ lọc dòng theo tên API thu hẹp những dòng có thể trích sai, nhưng việc hiểu đúng đối tượng và tham số vẫn cần đối chiếu ngữ cảnh. Cơ chế này mới hỗ trợ một số lời gọi .NET qua trường có kiểu đơn giản.

## Năm lượt qua trình duyệt thật

| Hồ sơ và lựa chọn | VM / Qwen | Thời gian | Điều đối chiếu được |
|---|---:|---:|---|
| Mercurial, agent chọn 261 | 2 / 3 | 5,373 s | Chỉ nhìn nơi gọi chưa đủ. Trong thân hàm ứng viên 1888–1911, dòng 1906 yêu cầu phản hồi trên đối tượng yêu cầu mạng. |
| Mercurial, chọn 245 | 2 / 2 | 3,870 s | Thân hàm 1913–1934 đọc từ luồng tệp ở dòng 1921. Dòng 1929 mới chuyển tiếp cho hàm phụ. Chưa có căn cứ cho thao tác gửi HTTP trực tiếp tại dòng này. |
| Mercurial, chọn 244 | 2 / 0 | 0,417 s | Bộ điều hướng chưa xác định được ứng viên. |
| Mercurial, chọn 272 | 2 / 2 | 3,569 s | Cùng thân hàm và dòng 1906 như lần chọn 261. Khi chấm, thân hàm chỉ được tính một lần. |
| Gomorrah, agent tự chọn | 4 / 3 | 4,900 s | Lần lượt kiểm 1070, 1067, 1056, hết ngân sách mà chưa xác định được thân hàm. |

Lượt VM trong bảng tính các lần gọi công cụ, gồm cả dịch ngược để xác nhận lại nguồn. Thời gian đo bắt đầu sau kiểm tra dịch vụ. Trình duyệt đã mở được trích dẫn, quay lại hồ sơ và mở các kết quả trên bản đồ ở chiều rộng 390 px. [Biên bản hai mẫu, hash và số token](../deliverables/real-demo-evidence/web-field-reviews.json)

## Đối chứng trên hai thân hàm khác nhau

Trong hai thân hàm Mercurial có hai thao tác mục tiêu được nguồn hỗ trợ và hai trường hợp phải giữ “chưa có dẫn chứng”. Đối chiếu riêng từng số dòng với ILSpy. Ở thân hàm đọc tệp, dòng 1919 mở luồng và dòng 1921 đọc nội dung. Ở thân hàm kia, dòng 1897 mở luồng của yêu cầu, dòng 1900 ghi qua luồng đó và dòng 1906 lấy phản hồi.

| Dữ liệu cấp cho model | Dẫn đúng thao tác có thật | Trả lời có thao tác nhưng dẫn sai | Trả lời thiếu căn cứ đúng chỗ |
|---|---:|---:|---:|
| Chỉ dòng gọi | 0/2 | 0 | 2/2 |
| Có thân hàm, được chọn mọi dòng | 1/2 | 2 | 1/2 |
| Có thân hàm, chọn dòng có lời gọi API phù hợp | 2/2 | 0 | 2/2 |

Đây là phép đo phát triển trên hai thân hàm đã xem khi thiết kế. Nhánh cuối thay cả ràng buộc trích dẫn lẫn cách diễn đạt câu hỏi HTTP. Chưa có phép thử tách riêng tác động của hai thay đổi. Dữ liệu này cũng chưa xác định việc gửi thành công, đích thực tế hoặc dữ liệu trình duyệt đã đi đến đích. Các chỉ số toàn báo cáo vẫn dùng bảng chấm ba mẫu. [Đối chứng toàn báo cáo](PHU_LUC_DIEU_TRA_NET.md)

Từ thư mục gốc, chạy `.\.venv\Scripts\python.exe -m eval.field_review_audit` để tính lại bảng. Trên máy giữ nhật ký riêng, thêm `--replay` để kiểm chuỗi hash, hồ sơ gốc, câu trả lời và số lượt model. Người chấm có thể xem hai lần thử và cả lần Qwen chọn sai trong cùng tệp biên bản.
