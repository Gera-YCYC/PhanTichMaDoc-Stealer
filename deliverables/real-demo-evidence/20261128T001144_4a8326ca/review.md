# Đối chiếu từng nhận định

Run ID `20261128T001144_4a8326ca`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Nạp assembly qua chuỗi chuyển đổi, lấy kiểu đầu tiên rồi gọi một phương thức theo tên. | Dòng 275 nạp dữ liệu sau bước chuyển đổi rồi chọn kiểu đầu tiên. Dòng 282–286 nối phương thức đã tra cứu, thao tác gọi và các đối số. | 273–278, 280–288, 211–231 | Đúng | Loại |
| C2 | Mô tả các bước thay dấu nối và khôi phục một mảng byte từ chuỗi Base32. | Các dòng 211–230 thể hiện bước chuẩn hóa và tạo mảng byte của hàm chuyển đổi. | 273–278, 280–288, 211–231 | Đúng | Loại |
| C3 | Gọi trình chuyển đổi hệ 16, tách các phần rồi ghép ký tự. | Dòng 275 chứa điểm gọi. Các dòng 52–57 tách văn bản, chuyển cơ số 16 và nối ký tự. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C4 | Gọi phương thức phản chiếu trên kiểu đã nạp và truyền hai đối số. | Dòng 282–286 xác nhận thao tác gọi cùng hai đối số. Chỉ tính nạp assembly khi câu khẳng định việc nạp. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C5 | Gọi BeginUpdate để hoãn cập nhật bố cục và tăng hiệu năng. | Các dòng 1614 và 1904–1906 xác nhận lời gọi và SuspendLayout. Lý do tăng hiệu năng khi xử lý hàng loạt là suy diễn. | 1604–1619, 1904–1908 | Thiếu căn cứ | Giữ |
| C6 | Nạp assembly bằng dữ liệu qua chuỗi hàm chuyển đổi. | Điểm nạp và các lời gọi lồng cùng xuất hiện ở dòng 275. Câu mô tả nguồn đầu vào. | 43–46, 273–278, 280–288 | Đúng | Loại |
| C7 | Gọi phương thức trên kiểu đã nạp với hai đối số cụ thể. | Các dòng 282–286 đủ để xác định lời gọi và hai đối số. | 43–46, 273–278, 280–288 | Đúng | Giữ |
| C8 | Gỡ phần tử khỏi tập nút cha của cây. | Dòng 1621 thao tác trên tập nút của nút cha. | 1610–1641 | Đúng | Giữ |
| C9 | Chèn nhiều nút vào tập nút của cây. | Các dòng 1635 và 1640 có thao tác chèn tập phần tử. | 1610–1641 | Đúng | Giữ |
| C10 | Gọi hàm gửi thông điệp cuộn dọc xuống một dòng. | Khai báo ở 919–920 và đối số ở 926 phù hợp thông điệp WM_VSCROLL và SB_LINEDOWN của Win32. | 911–942 | Đúng | Giữ |
| C11 | Hủy đăng ký hàm xử lý sự kiện nhả chuột. | Dòng 3173 dùng phép gỡ đăng ký. Đoạn chứng cứ cũng chứa điểm thêm đăng ký trước đó. | 3148–3175 | Đúng | Giữ |
| C12 | Hủy đăng ký hàm xử lý sự kiện di chuyển chuột. | Dòng 3174 dùng phép gỡ đăng ký cho sự kiện được nêu. | 3148–3175 | Đúng | Giữ |
| C13 | Gọi hàm chuyển hệ 16 với chuỗi ASCII được ghi cứng. | Trích dẫn 36–67 có khai báo và thân hàm nhận đối số. Nó chưa cho thấy lời gọi tại điểm truyền chuỗi ghi cứng, cũng chưa ràng buộc miền ký tự ASCII. | 36–67 | Thiếu căn cứ | Giữ |
| C14 | Gọi phương thức theo tên trên kiểu của assembly được nạp sau bước chuyển đổi. | Dòng 282–283 gọi phương thức và dòng 275 xác định nguồn kiểu từ assembly đã nạp. | 255–286 | Đúng | Giữ |
| C15 | Truyền hai đối số cụ thể vào phương thức được gọi. | Dòng 283–286 thể hiện danh sách đối số. | 255–286 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

interop-declaration, manifest-stream, method-lookup, resource-object, smtp-exfil
