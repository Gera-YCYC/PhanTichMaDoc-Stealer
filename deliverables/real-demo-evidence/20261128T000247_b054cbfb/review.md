# Đối chiếu từng nhận định

Run ID `20261128T000247_b054cbfb`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Gọi hàm xử lý cookie, sao chép cơ sở dữ liệu của Chrome và đọc bảng cookie. | Dòng 75 gọi hàm. Các dòng 713–720 xác định nguồn và đích sao chép. Dòng 728 chọn bảng dữ liệu. | 65–80, 709–744, 282–286 | Đúng | Giữ |
| C2 | Chuyển thông tin phần cứng vào hàm và cho rằng dữ liệu đi ra qua webhook. | Dòng 285 xác nhận kiểu đối tượng và lời gọi. Các dòng dẫn trong câu chưa nối được lời gọi với yêu cầu mạng. | 65–80, 709–744, 282–286 | Thiếu căn cứ | Loại |
| C3 | Sao chép tệp Login Data của Chrome vào thư mục tạm. | Đường dẫn nguồn và thao tác sao chép có mặt ở dòng 779 và 787. | 66–81, 775–810 | Đúng | Giữ |
| C4 | Dùng khóa chính để thử giải mã mật khẩu đã lưu. | Trích dẫn dừng ở dòng 810 sau khi lấy khóa. Điểm dùng khóa ở dòng 812 nằm ngoài chứng cứ của câu. | 66–81, 775–810 | Thiếu căn cứ | Loại |
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

## Mục bị bỏ sót trên đáp án đã chốt

browser-technique, cookie-technique, login-table, post-body, webhook-config
