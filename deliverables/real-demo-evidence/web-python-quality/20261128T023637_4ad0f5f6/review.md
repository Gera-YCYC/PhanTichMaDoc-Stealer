# Đối chiếu từng nhận định

Run ID `20261128T023637_4ad0f5f6`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Tạo bản nén trong thư mục tạm. | Tên, định dạng và thư mục nguồn khớp đối số ở dòng 279. | 313–328, 82–113, 276–286, 10, 16, 14 | Đúng | Giữ |
| C2 | Đưa bản nén vào thông điệp MIME rồi gọi gửi. | Đối chiếu tệp trả về, đối số tệp đính kèm, mã hóa phần MIME và lời gọi gửi trong các trích dẫn của câu. | 313–328, 82–113, 276–286, 10, 16, 14 | Đúng | Giữ |
| C3 | Nêu tên máy chủ được cấu hình. | Giá trị khớp mục IOC đã chốt và biến được dùng trong lời gọi tạo kết nối. | 313–328, 82–113, 276–286, 10, 16, 14 | Đúng | Giữ |
| C4 | Lọc các bản ghi tự động điền có giá trị. | Biểu thức điều kiện của truy vấn hiện ở dòng 247. | 295–310, 233–259, 270–273, 9 | Đúng | Giữ |
| C5 | Đọc kết quả truy vấn tự động điền vào biến. | Dòng 248 dùng cùng con trỏ với dòng 247. Bộ 36 mục chỉ chấm truy vấn ở vị trí này. | 295–310, 233–259, 270–273, 9 | Đúng | Giữ |
| C6 | Truy vấn ba trường dữ liệu đăng nhập. | Dòng 142 có đủ ba trường tương ứng mục tham chiếu. | 289–304, 134–154, 69–75, 9, 12 | Đúng | Giữ |
| C7 | Xử lý trường mật khẩu rồi trả về bytes. | Tham số và phép xử lý có căn cứ. Dòng 74 gán lại giá trị sau giải mã văn bản, dòng 75 trả về giá trị đó. Kiểu trả về nêu trong câu là sai. | 289–304, 134–154, 69–75, 9, 12 | Sai | Loại |
| C8 | Ghi nội dung vào tệp của hồ sơ trình duyệt. | Đoạn 116–131 bao gồm điều kiện, đường dẫn và thao tác ghi. | 298–313, 116–131 | Đúng | Giữ |
| C9 | Ghi nối vào tệp tự động điền tổng hợp. | Điều kiện và chế độ mở để ghi nối xuất hiện trong cùng đoạn dẫn. | 298–313, 116–131 | Đúng | Giữ |
| C10 | Nêu import Windows và gán mục đích sử dụng. | Phần trích xác nhận import. Theo quy ước chấm, mục đích sử dụng cần chứng cứ ngoài danh sách khai báo. | 5–32 | Thiếu căn cứ | Giữ |
| C11 | Nêu import mật mã và gán mục đích mã hóa. | Import có thật. Phần trích chưa chứng minh phép mã hóa được dùng trong chương trình. | 5–32 | Thiếu căn cứ | Giữ |
| C12 | Nêu phép giải mã và cho rằng không có bước giải mã văn bản. | Phép xử lý có trong thân hàm. Thân hàm không kiểm thẻ xác thực, nhưng có bước đổi kết quả sang văn bản tại dòng 74. | 58–89, 12 | Sai | Giữ |
| C13 | Suy ra việc gửi thư từ đoạn cấu hình. | Các trường cấu hình xuất hiện, nhưng trích dẫn kết thúc ở dòng 89, trước lời gọi gửi. | 58–89, 12 | Thiếu căn cứ | Loại |
| C14 | Nêu một tên máy chủ làm IOC tĩnh. | Tên máy chủ khớp giá trị khai báo và đáp án A27. Câu chỉ nêu chỉ dấu. | 58–89, 12 | Đúng | Giữ |
| C15 | Truy vấn dữ liệu tự động điền và gán kết quả. | Dòng 247 chứa điều kiện, dòng 248 đọc từ đúng con trỏ. | 248–279, 9, 245, 246, 247, 10 | Đúng | Giữ |
| C16 | Ghi kết quả tự động điền vào tệp được đặt tên. | Dòng 257 truyền tên và dữ liệu cho hàm ghi, các dòng 270–273 hiện thực đường dẫn và thao tác ghi. Đọc cả hai đoạn thì nhận định có căn cứ. | 248–279, 9, 245, 246, 247, 10 | Đúng | Loại |
| C17 | Gán T1555.003 cho việc truy cập kho đăng nhập trình duyệt. | Nguồn riêng của câu có đường dẫn kho đăng nhập, truy vấn trường mật khẩu và đọc hàng kết quả. Kết luận giới hạn ở khả năng truy cập tĩnh. | 131–147 | Đúng | Giữ |
| C18 | Đọc hàng sau truy vấn đăng nhập. | Dòng 142–143 dùng cùng con trỏ. | 9, 140, 141, 142, 143 | Đúng | Giữ |
| C19 | Đọc hàng sau truy vấn tự động điền. | Cùng thao tác đã chấm cho câu đọc kết quả tại dòng 248. | 9, 245, 246, 247, 248 | Đúng | Giữ |
| C20 | Thực hiện truy vấn đăng nhập. | Trùng truy vấn tại dòng 142. | 9, 140, 141, 142 | Đúng | Giữ |
| C21 | Thực hiện truy vấn tự động điền. | Trùng truy vấn tại dòng 247. | 9, 245, 246, 247 | Đúng | Giữ |
| C22 | Mở cơ sở dữ liệu theo biểu thức đường dẫn tạm. | Có lời gọi ở dòng 245. Đây là một mục ngoài đáp án chốt. | 9, 245 | Đúng | Giữ |
| C23 | Sao chép giữa hai biểu thức đường dẫn. | Dòng 244 xác nhận thao tác. Câu và trích dẫn thiếu nguồn gốc đường dẫn cần để tính A32. | 10, 244 | Đúng | Giữ |
| C24 | Ghi vào tệp văn bản của hồ sơ. | Dòng 123–124 xác nhận thao tác ghi hẹp. Thiếu điều kiện và ngữ cảnh của A15. | 123, 124 | Đúng | Giữ |
| C25 | Ghi từng mục đã định dạng vào tệp tạm theo tên tham số. | Đường dẫn và biểu thức ghi tương ứng A36 ở dòng 271 và 273. | 271, 273 | Đúng | Giữ |
| C26 | Ghi nội dung vào tệp tổng hợp. | Câu chỉ khẳng định thao tác ghi. Áp dụng cùng cách chấm giới hạn đã dùng ở v11. | 128, 129 | Đúng | Giữ |
| C27 | Tạo bản nén ZIP. | Dòng 279 xác nhận cùng thao tác đã chấm ở đầu báo cáo. | 10, 279 | Đúng | Giữ |
| C28 | Gọi phép giải mã trong hàm xử lý. | Hai dòng 72–73 và import tương ứng xác nhận chế độ và vai trò đối số. Câu không khẳng định kiểu trả về. | 12, 72, 73 | Đúng | Giữ |
| C29 | Thêm nội dung văn bản vào thông điệp. | Dòng 94 gắn phần văn bản vào thông điệp nhiều phần. | 16, 90, 94 | Đúng | Giữ |
| C30 | Gọi API gửi thông điệp. | Dòng 109 xác nhận đối số gửi và đối tượng đã tạo ở 106. | 14, 106, 109 | Đúng | Giữ |
| C31 | Gọi phương thức xác thực trên đối tượng thư. | Dòng 108 cho thấy lời gọi và hai vị trí đối số. | 14, 106, 108 | Đúng | Giữ |
| C32 | Yêu cầu nâng cấp kết nối TLS. | Đối tượng tạo ở 106 nhận lời gọi tại 107. | 14, 106, 107 | Đúng | Giữ |
| C33 | Tạo đối tượng SMTP theo cấu hình. | Dòng 106 có các đối số máy chủ và cổng. | 14, 106 | Đúng | Giữ |
| C34 | Đặt payload theo biểu thức đọc. | Dòng 98 có biểu thức đọc làm đối số. Câu không dẫn dòng 96 để xác định nguồn đường dẫn của A19. | 17, 97, 98 | Đúng | Giữ |
| C35 | Đọc tệp được chỉ định bởi tham số đường dẫn. | Các dòng 96 và 98 chứng minh thao tác đọc. Câu chỉ khẳng định việc đọc, chưa khẳng định việc đặt dữ liệu vào payload theo A19. | 96, 98 | Đúng | Giữ |
| C36 | Mã hóa thành phần MIME. | Dòng 100 xác nhận lời gọi này, ngoài các mục đã chốt. | 18, 100 | Đúng | Giữ |
| C37 | Tuần tự hóa thông điệp. | Đối tượng được tạo ở 90, tuần tự hóa ở 103. | 16, 90, 103 | Đúng | Giữ |
| C38 | Gắn thành phần MIME vào thông điệp. | Dòng 102 xác nhận lời gọi trên đúng đối tượng. | 16, 90, 102 | Đúng | Giữ |
| C39 | Mở bản sao cơ sở dữ liệu đăng nhập. | Dòng 140 có lời gọi mở cơ sở dữ liệu với đường dẫn tạm tương ứng. | 9, 140 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

PY24-A01, PY24-A02, PY24-A03, PY24-A05, PY24-A10, PY24-A11, PY24-A12, PY24-A13, PY24-A14, PY24-A16, PY24-A17, PY24-A19, PY24-A29, PY24-A31, PY24-A32, PY24-A34
