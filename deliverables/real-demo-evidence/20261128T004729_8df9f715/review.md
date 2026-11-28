# Đối chiếu từng nhận định

Run ID `20261128T004729_8df9f715`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Gọi hàm xử lý cookie, sao chép cơ sở dữ liệu cookie Chrome tới tệp tạm rồi đọc bảng cookie. | Dòng 75 gọi hàm. Đoạn 713–720 xác định bản sao. Dòng 727–728 mở bản sao và chọn bảng. | 65–80, 709–744, 282–286 | Đúng | Loại |
| C2 | Gọi hàm xử lý mật khẩu và suy đoán mục đích lấy mật khẩu đã lưu. | Dòng 76 xác nhận lời gọi. Các đoạn còn lại mô tả cookie và thông tin hệ thống. Thân hàm xử lý mật khẩu nằm ngoài trích dẫn của câu. | 65–80, 709–744, 282–286 | Thiếu căn cứ | Loại |
| C3 | Sao chép tệp Login Data của Chrome đến vị trí tạm. | Đường dẫn nguồn ở dòng 779, đích tạm ở 783–784 và thao tác sao chép ở 787. | 66–81, 775–810 | Đúng | Giữ |
| C4 | Đọc bảng logins bằng SQLite trên bản sao của tệp Login Data. | Dòng 779–787 nối tệp nguồn với bản sao. Dòng 795–796 mở bản sao và đọc bảng logins. | 66–81, 775–810 | Đúng | Giữ |
| C5 | Gọi API giải mã với dữ liệu mã hóa, khóa và thẻ xác thực. | Các dòng 382–385 thể hiện đối số và lời gọi API. | 375–388, 407–417, 453–470 | Đúng | Loại |
| C6 | Đọc thuộc tính độ dài thẻ xác thực từ bộ cung cấp mật mã. | Trích dẫn chứa cả lần chọn thuộc tính lẫn lời gọi API đọc thuộc tính. | 375–388, 407–417, 453–470 | Đúng | Giữ |
| C7 | Mở bộ cung cấp AES và cấu hình chế độ GCM. | Dòng 380 chọn AES/GCM. Đoạn 419–436 chứa thao tác cấu hình. | 375–385, 419–436, 438–451 | Đúng | Giữ |
| C8 | Nhập khóa vào bộ cung cấp mật mã. | Lời gọi nhập khóa nằm ở dòng 445. | 375–385, 419–436, 438–451 | Đúng | Giữ |
| C9 | Truyền đường dẫn tệp cookie và kiểu nội dung multipart vào hàm SendData. | Dòng 761 xác nhận đường dẫn và hai vai trò đối số được nêu. | 753–784 | Đúng | Giữ |
| C10 | Truyền thông điệp của ngoại lệ cho hàm Send. | Các dòng 765–768 nối nhánh bắt lỗi với đối số của hàm. | 753–784 | Đúng | Giữ |
| C11 | Gửi tệp mật khẩu theo kiểu multipart qua hàm SendData. | Dòng 826 xác nhận lời gọi, tệp và kiểu nội dung. Để xác nhận hiệu ứng gửi cần kiểm tra tiếp thân hàm. | 817–848 | Thiếu căn cứ | Giữ |
| C12 | Gửi thông báo lỗi qua hàm Send. | Dòng 833 truyền trường Message của ngoại lệ. Trích dẫn thiếu phần hàm thực hiện truyền. | 817–848 | Thiếu căn cứ | Loại |
| C13 | Truyền đối tượng thông tin IP và vị trí cho hàm xử lý nội dung. | Lời gọi và các trường dữ liệu được nêu cùng ở dòng 279. | 264–295 | Đúng | Giữ |
| C14 | Truyền đối tượng thông tin hệ điều hành và phần cứng cho hàm xử lý nội dung. | Đối tượng ở dòng 285 có các trường được nêu. | 264–295 | Đúng | Giữ |
| C15 | Giải mã trường dữ liệu cookie qua hàm cục bộ với khóa chính. | Đoạn mã chứng minh dữ liệu và khóa được truyền vào helper. Thân hàm quyết định hiệu ứng giải mã nằm ngoài trích dẫn. | 732–763 | Thiếu căn cứ | Loại |
| C16 | Gửi tệp cookie trong thư mục tạm qua SendData. | Dòng 761 chứng minh thao tác chuyển đối số. Đoạn này thiếu thân hàm để xác nhận tác dụng truyền dữ liệu. | 732–763 | Thiếu căn cứ | Loại |
| C17 | Giải mã mật khẩu bằng khóa do hàm GetMasterKey trả về. | Dòng 807 lấy khóa và dòng 812 chuyển khóa cùng dữ liệu mật khẩu cho helper. Tác dụng giải mã chưa được chứng minh bởi các dòng của câu. | 797–828 | Thiếu căn cứ | Giữ |
| C18 | Chuyển mật khẩu đã giải mã đến máy chủ từ xa qua hàm nhận dữ liệu multipart. | Lời gọi ở dòng 826 xác nhận tệp và kiểu multipart. Trích dẫn không xác minh trạng thái nội dung của tệp hay đích đến. | 797–828 | Thiếu căn cứ | Loại |
| C19 | Gán kỹ thuật ATT&CK T1539 cho việc thu thập cookie phiên trình duyệt. | T1539 phù hợp với toàn bộ hàm. Ba đoạn trích cho thấy kho cookie, bảng SQLite và hàm xử lý giá trị. Chúng thiếu dòng 720 nối kho gốc với bản sao được đọc và thiếu phần xuất kết quả. Theo quy tắc chấm trên chính chứng cứ của câu, chuỗi này chưa đủ. | 709–717, 724–732, 743–751 | Thiếu căn cứ | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

browser-technique, cookie-technique, post-body, webhook-config
