# Đối chiếu từng nhận định

Run ID `20261128T003743_f8acf7f0`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Lấy danh sách các nút từ dữ liệu của sự kiện kéo. | Dòng 1603–1605 kiểm và đọc danh sách từ dữ liệu sự kiện. | 1602–1617, 1350–1385 | Đúng | Giữ |
| C2 | Kiểm tra cây sở hữu nút đầu và tính hợp lệ của thao tác thả. | Hai phép kiểm nằm trong điều kiện ở dòng 1612. | 1602–1617, 1350–1385 | Đúng | Giữ |
| C3 | Gọi bộ giải mã chuỗi và kết hợp các bit để dựng mảng byte. | Dòng 275 gọi bộ chuyển đổi, các dòng 211–230 thể hiện cách xử lý dữ liệu. | 273–278, 211–231, 280–288 | Đúng | Giữ |
| C4 | Gọi phương thức trên kiểu lấy từ assembly được nạp và chuyển hai đối số. | Các dòng 275, 282–286 xác nhận nguồn kiểu, lời gọi và đối số. | 273–278, 211–231, 280–288 | Đúng | Loại |
| C5 | Gọi trình chuyển đổi hệ 16, tách các phần rồi ghép ký tự. | Dòng 275 chứa điểm gọi. Các dòng 52–57 tách văn bản, chuyển cơ số 16 và nối ký tự. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C6 | Gọi phương thức theo tên và chuyển hai đối số. | Các dòng 282–286 thể hiện lời gọi và hai đối số. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C7 | Gọi BeginUpdate để hoãn cập nhật bố cục và tăng hiệu năng. | Các dòng 1614 và 1904–1906 xác nhận lời gọi và SuspendLayout. Lý do tăng hiệu năng khi xử lý hàng loạt là suy diễn. | 1604–1619, 1904–1908 | Thiếu căn cứ | Giữ |
| C8 | Gỡ control con khỏi tập control của cha. | Dòng 570 thực hiện đúng thao tác gỡ. | 547–578 | Đúng | Giữ |
| C9 | Khai báo hàm tách văn bản hệ 16 và chuyển từng phần thành ký tự. | Các dòng 48–60 chứng minh định nghĩa và cách chuyển đổi. | 30–61 | Đúng | Giữ |
| C10 | Khởi tạo một đối tượng trong phương thức bố trí giao diện. | Dòng 3086 khai báo phương thức, dòng 3088 tạo đối tượng. | 3073–3104 | Đúng | Giữ |
| C11 | Gỡ control của mỗi nút khi duyệt cây. | Các dòng 568–570 xác nhận gỡ control trong lần duyệt từng nút. | 564–595 | Đúng | Giữ |
| C12 | Gọi hàm gửi thông điệp cuộn dọc xuống một dòng. | Khai báo ở 919–920 và đối số ở 926 phù hợp thông điệp WM_VSCROLL và SB_LINEDOWN của Win32. | 911–942 | Đúng | Giữ |
| C13 | Hủy đăng ký hàm xử lý sự kiện nhả chuột. | Dòng 3173 dùng phép gỡ đăng ký. Đoạn chứng cứ cũng chứa điểm thêm đăng ký trước đó. | 3148–3175 | Đúng | Giữ |
| C14 | Hủy đăng ký hàm xử lý sự kiện di chuyển chuột. | Dòng 3174 dùng phép gỡ đăng ký cho sự kiện được nêu. | 3148–3175 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

interop-declaration, manifest-stream, method-lookup, resource-object, smtp-exfil
