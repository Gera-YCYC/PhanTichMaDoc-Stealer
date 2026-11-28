# Đối chiếu từng nhận định

Run ID `20261128T012820_c485ff68`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Gọi hàm xử lý cookie, sao chép cơ sở dữ liệu cookie Chrome tới tệp tạm rồi đọc bảng cookie. | Dòng 75 gọi hàm. Đoạn 713–720 xác định bản sao. Dòng 727–728 mở bản sao và chọn bảng. | 65–80, 709–744, 282–286 | Đúng | Loại |
| C2 | Gọi hàm xử lý mật khẩu rồi suy đoán mục đích lấy mật khẩu đã lưu. | Dòng 76 có lời gọi. Phần mã nêu trong câu thiếu thân hàm xử lý mật khẩu. | 65–80, 709–744, 282–286 | Thiếu căn cứ | Loại |
| C3 | Tạo yêu cầu multipart chứa nội dung tệp và trường mô tả, rồi xác định đích là một webhook. | Các dòng 1919–1929 chuẩn bị multipart, đoạn 1728–1752 tạo POST và ghi vào luồng yêu cầu. Dòng 1929 dùng biến địa chỉ. Các trích dẫn của câu chưa giải được giá trị của biến đó. | 1919–1934, 1724–1731, 1733–1761 | Thiếu căn cứ | Giữ |
| C4 | Tạo POST, đặt user-agent, đính kèm các trường tệp và khẳng định đích webhook. | Dòng 1744–1752 xác nhận phương thức, user-agent và ghi yêu cầu. Các trường riêng có ở 1924–1927. URL ở 1929 là một biến và địa chỉ khởi tạo nằm ngoài đoạn trích. | 1919–1934, 1724–1731, 1733–1761 | Thiếu căn cứ | Giữ |
| C5 | Liệt kê địa chỉ của ảnh đại diện làm IOC. | Dòng 1928 xác nhận URL là ảnh đại diện. Khi chấm đúng loại IOC theo mục tiêu kênh gửi, gán địa chỉ tài nguyên hiển thị vào danh sách IOC là sai loại. Literal trong tệp là có thật. | 1919–1934, 1724–1731, 1733–1761 | Sai | Giữ |
| C6 | Sao chép tệp Login Data của Chrome đến vị trí tạm. | Đường dẫn nguồn ở dòng 779, đích tạm ở 783–784 và thao tác sao chép ở 787. | 66–81, 775–810 | Đúng | Giữ |
| C7 | Đọc bảng logins từ bản sao Login Data qua SQLite. | Dòng 779–787 xác định nguồn và sao chép tệp. Dòng 795–796 mở bản sao và đọc bảng. | 66–81, 775–810 | Đúng | Giữ |
| C8 | Gọi hàm cookie và suy ra rằng hàm lấy cookie trình duyệt. | Dòng 75 xác nhận lời gọi. Trích dẫn của câu dừng ở phía gọi và các hàm khác. Phần đọc cơ sở dữ liệu cookie nằm ngoài các đoạn đã nêu. | 62–77, 248–268, 275–280 | Thiếu căn cứ | Loại |
| C9 | Gọi hai hàm xử lý nội dung token và suy ra việc truyền token tới webhook. | Dòng 259–261 cho thấy hai lời gọi cùng dữ liệu chuyển giữa chúng. Đoạn trích thiếu thao tác mạng và cấu hình đích của hàm nhận nội dung. | 62–77, 248–268, 275–280 | Thiếu căn cứ | Loại |
| C10 | Truyền đường dẫn tệp cookie và kiểu nội dung multipart vào hàm SendData. | Dòng 761 xác nhận đường dẫn và hai vai trò đối số được nêu. | 753–784 | Đúng | Giữ |
| C11 | Truyền thông điệp của ngoại lệ cho hàm Send. | Các dòng 765–768 nối nhánh bắt lỗi với đối số của hàm. | 753–784 | Đúng | Giữ |
| C12 | Gửi tệp mật khẩu theo kiểu multipart qua hàm SendData. | Dòng 826 xác nhận lời gọi, tệp và kiểu nội dung. Để xác nhận hiệu ứng gửi cần kiểm tra tiếp thân hàm. | 817–848 | Thiếu căn cứ | Giữ |
| C13 | Gửi thông báo lỗi qua hàm Send. | Dòng 833 truyền trường Message của ngoại lệ. Trích dẫn thiếu phần hàm thực hiện truyền. | 817–848 | Thiếu căn cứ | Loại |
| C14 | Gọi hàm cookie rồi diễn giải lời gọi thành hành vi lấy cookie. | Dòng 75 xác nhận lời gọi. Phần thân hàm đọc kho cookie nằm ngoài các dòng 63–94. | 63–94 | Thiếu căn cứ | Loại |
| C15 | Gọi hàm mật khẩu rồi diễn giải lời gọi thành hành vi lấy mật khẩu. | Dòng 76 xác nhận lời gọi. Trích dẫn 63–94 thiếu thân hàm để kiểm phần diễn giải. | 63–94 | Thiếu căn cứ | Loại |
| C16 | Sao chép kho cookie của Chrome sang cookies.db trong thư mục tạm. | Các dòng 713–714 tạo đường dẫn nguồn và đích từ biến thư mục tạm. Dòng 720 thực hiện phép sao chép. | 693–724 | Đúng | Giữ |
| C17 | Thử giải mã một mảng byte qua ProtectedData.Unprotect. | Dòng 696–700 chuẩn bị mảng đầu vào và gọi đúng API. Câu chỉ mô tả một lần thử. | 693–724 | Đúng | Giữ |
| C18 | Mở luồng để đọc tệp theo đối số đường dẫn. | Các dòng 1919–1921 mở luồng và đọc nội dung tệp vào mảng. | 1911–1935 | Đúng | Giữ |
| C19 | Gửi multipart qua helper và liệt kê các trường trong từ điển. | Dòng 1924–1929 cho thấy cấu trúc từ điển và lời gọi hàm. Trích dẫn 1911–1935 thiếu thân hàm ghi yêu cầu ra mạng. | 1911–1935 | Thiếu căn cứ | Giữ |
| C20 | Đưa URL tĩnh làm ứng viên IOC. | URL tồn tại ở dòng 1928 dưới trường ảnh đại diện. Tính như C5 khi chấm độ liên quan của IOC với kênh gửi. Hai câu lặp cùng một chỉ báo sai loại, được gộp khi tính theo đơn vị. | 1911–1935 | Sai | Giữ |
| C21 | Gán T1539 cho luồng thu thập cookie phiên. | Hai trích dẫn liền nhau 709–730 và 731–751 xác định kho Chrome, đích sao chép, phép sao chép ở 720, thao tác đọc bảng ở 727–728 và xử lý giá trị ở 747. Bằng chứng đủ cho kỹ thuật thu thập cookie trong mã tĩnh. | 709–730, 731–751 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

aes-provider, browser-technique, cookie-key-call, hardware-message, ip-message, key-import, login-key-call, native-decrypt, post-body, tag-length, webhook-config
