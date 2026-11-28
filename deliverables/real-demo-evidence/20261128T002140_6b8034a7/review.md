# Đối chiếu từng nhận định

Run ID `20261128T002140_6b8034a7`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Ánh xạ ký tự Base32 bằng nhánh chọn rồi thêm kết quả số vào danh sách byte. | Dòng 218 và 235 xác nhận ánh xạ. Các dòng 219–223 thêm từng bit riêng, khác với thêm trực tiếp giá trị đã ánh xạ. | 211–223, 233–268 | Sai | Giữ |
| C2 | Tách từng bit, thêm vào danh sách và dùng danh sách để dựng mảng byte cuối. | Các dòng 219–223 xác nhận tách bit. Điểm dùng danh sách dựng mảng cuối ở 225–230 nằm ngoài hai trích dẫn. | 211–223, 233–268 | Thiếu căn cứ | Giữ |
| C3 | Nạp assembly sau các phép đổi biểu diễn rồi lấy kiểu đầu tiên. | Dòng 275 chứng minh thao tác nạp và truy xuất kiểu ở vị trí đầu. | 273–278, 280–288, 211–231 | Đúng | Giữ |
| C4 | Gọi phương thức trên kiểu đã nạp với hai đối số. | Dòng 282–286 cho thấy thao tác gọi và đối số. | 273–278, 280–288, 211–231 | Đúng | Giữ |
| C5 | Gọi hàm chuyển hệ 16 rồi chuyển từng phần thành ký tự. | Dòng 275 là điểm gọi. Các dòng 52–57 chứng minh tách và chuyển đổi. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C6 | Gọi phương thức bằng phản chiếu và truyền hai đối số. | Dòng 282–286 xác nhận thao tác và các đối số. | 273–278, 48–60, 280–288 | Đúng | Giữ |
| C7 | Nạp assembly bằng dữ liệu qua chuỗi hàm chuyển đổi. | Điểm nạp và các lời gọi lồng cùng xuất hiện ở dòng 275. Câu mô tả nguồn đầu vào. | 43–46, 273–278, 280–288 | Đúng | Loại |
| C8 | Gọi phương thức trên kiểu đã nạp với hai đối số cụ thể. | Các dòng 282–286 đủ để xác định lời gọi và hai đối số. | 43–46, 273–278, 280–288 | Đúng | Giữ |
| C9 | Gọi hàm chuyển hệ 16 với một chuỗi được ghi cứng. | Đoạn 35–66 có định nghĩa hàm. Điểm gọi truyền một hằng chuỗi chưa được dẫn chứng. | 35–66 | Thiếu căn cứ | Giữ |
| C10 | Gọi hàm gửi thông điệp cuộn dọc xuống một dòng. | Khai báo ở 919–920 và đối số ở 926 phù hợp thông điệp WM_VSCROLL và SB_LINEDOWN của Win32. | 905–936 | Đúng | Giữ |
| C11 | Hủy đăng ký hàm xử lý sự kiện nhả chuột. | Dòng 3173 dùng phép gỡ đăng ký. Đoạn chứng cứ cũng chứa điểm thêm đăng ký trước đó. | 3146–3177 | Đúng | Giữ |
| C12 | Hủy đăng ký hàm xử lý sự kiện di chuyển chuột. | Dòng 3174 dùng phép gỡ đăng ký cho sự kiện được nêu. | 3146–3177 | Đúng | Giữ |
| C13 | Hủy đăng ký hàm xử lý sự kiện di chuyển chuột. | Dòng 3174 xác nhận thao tác. Đây là cùng thao tác với C12. | 3171–3202 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

interop-declaration, manifest-stream, method-lookup, resource-object, smtp-exfil
