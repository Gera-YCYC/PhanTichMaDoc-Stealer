# Đối chiếu từng nhận định

Run ID `20261128T002926_2b0e57f6`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Xóa dấu nối trong chuỗi đầu vào. | Dòng 213 thay dấu nối bằng chuỗi rỗng. | 211–223, 233–268 | Đúng | Giữ |
| C2 | Ánh xạ các ký tự của chuỗi sang giá trị số. | Dòng 216–218 chuyển ký tự qua hàm có nhánh chọn ở 235. | 211–223, 233–268 | Đúng | Giữ |
| C3 | Nạp assembly bằng dữ liệu đã chuyển đổi rồi lấy kiểu đầu tiên. | Dòng 275 thực hiện cả hai thao tác. | 273–278, 280–288, 211–231 | Đúng | Giữ |
| C4 | Gọi phương thức phản chiếu với hai đối số. | Dòng 282–286 xác nhận thao tác và đối số. | 273–278, 280–288, 211–231 | Đúng | Giữ |
| C5 | Gọi trình chuyển đổi hệ 16, tách các phần rồi ghép ký tự. | Dòng 275 chứa điểm gọi. Các dòng 52–57 tách văn bản, chuyển cơ số 16 và nối ký tự. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C6 | Gọi phương thức đã tra theo tên và truyền hai đối số. | Dòng 282–286 xác nhận lời gọi và danh sách đối số. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C7 | Gọi BeginUpdate để hoãn cập nhật bố cục và tăng hiệu năng. | Các dòng 1614 và 1904–1906 xác nhận lời gọi và SuspendLayout. Lý do tăng hiệu năng khi xử lý hàng loạt là suy diễn. | 1604–1619, 1904–1908 | Thiếu căn cứ | Giữ |
| C8 | Gỡ phần tử khỏi tập nút cha của cây. | Dòng 1621 thao tác trên tập nút của nút cha. | 1610–1641 | Đúng | Giữ |
| C9 | Chèn nhiều nút vào tập nút của cây. | Các dòng 1635 và 1640 có thao tác chèn tập phần tử. | 1610–1641 | Đúng | Giữ |
| C10 | Gọi hàm phụ từ hàm khởi tạo. | Dòng 43–45 cho thấy hàm khởi tạo thực hiện lời gọi. | 30–61 | Đúng | Giữ |
| C11 | Gọi hàm gửi thông điệp cuộn dọc xuống một dòng. | Khai báo ở 919–920 và đối số ở 926 phù hợp thông điệp WM_VSCROLL và SB_LINEDOWN của Win32. | 911–942 | Đúng | Giữ |
| C12 | Hủy đăng ký hàm xử lý sự kiện nhả chuột. | Dòng 3173 dùng phép gỡ đăng ký. Đoạn chứng cứ cũng chứa điểm thêm đăng ký trước đó. | 3148–3175 | Đúng | Giữ |
| C13 | Hủy đăng ký hàm xử lý sự kiện di chuyển chuột. | Dòng 3174 dùng phép gỡ đăng ký cho sự kiện được nêu. | 3148–3175 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

interop-declaration, manifest-stream, method-lookup, resource-object, smtp-exfil
