# Đối chiếu từng nhận định

Run ID `20261128T031606_ca91de35`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Sao chép tệp Login Data của Chrome vào thư mục tạm. | Đường dẫn nguồn và thao tác sao chép có mặt ở dòng 779 và 787. | 66–81, 775–810 | Đúng | Giữ |
| C2 | Đọc bảng đăng nhập từ tệp SQLite. | Đoạn 779–796 cho thấy bản sao tệp, lúc mở cơ sở dữ liệu và tên bảng được chọn. | 66–81, 775–810 | Đúng | Giữ |
| C3 | Đọc trường khóa từ trạng thái Chrome bằng biểu thức chính quy. | Dòng 681 xác định tệp nguồn. Dòng 687 đọc tệp và tìm trường khóa. Dòng 693 xác nhận cách biểu diễn bằng Base64. | 737–752, 676–707 | Đúng | Giữ |
| C4 | Gọi API bảo vệ dữ liệu để thu lại khóa chính. | Dòng 693–700 cho thấy bước chuẩn bị đầu vào và trả kết quả Unprotect trong thân hàm lấy khóa. | 737–752, 676–707 | Đúng | Giữ |
| C5 | Truy vấn WMI để lấy tên, kiến trúc và phiên bản hệ điều hành. | Lớp được truy vấn hiện ở 1106. Các trường Caption, OSArchitecture và Version xuất hiện ở 1113–1123. | 1076–1083, 1100–1131, 1133–1140 | Đúng | Giữ |
| C6 | Khẳng định đã ghi dữ liệu giải mã ra tệp văn bản tạm. | Dòng 797 mở bộ ghi. Đến 812, đoạn dẫn chưa có thao tác ghi giá trị đã giải mã vào bộ ghi đó. | 797–812, 676–707 | Thiếu căn cứ | Loại |
| C7 | Đọc khóa từ trạng thái của Chrome rồi dùng Unprotect. | Đường dẫn và phép đọc ở 681–687, sau đó dữ liệu được chuẩn bị và chuyển vào Unprotect tại 693–700. | 797–812, 676–707 | Đúng | Loại |
| C8 | Gọi hàm giải mã AES-GCM với các đối số nêu trong nhận định. | Đối tượng ở 667 và lời gọi cụ thể ở 668 xác nhận bốn đối số. Đây là lời gọi ở tầng sử dụng thư viện. | 665–696 | Đúng | Loại |
| C9 | Đọc trường khóa từ tệp trạng thái và chuyển giá trị Base64 thành byte. | Dòng 681–687 xác nhận nguồn và cách lấy dữ liệu. Dòng 693 chuyển dữ liệu Base64 thành byte. | 665–696 | Đúng | Giữ |
| C10 | Giải mã một vùng byte theo cấu hình và gán nội dung phần tử bảng. | Điều kiện ở 1386 và phép gán ở 1388 khớp bộ mã mặc định, mảng, chỉ số và trường đích. | 1374–1403 | Đúng | Giữ |
| C11 | Gán tên mục bảng từ vùng byte được giải mã bằng bộ mã mặc định. | Dòng 1507 chứa phép gán trường tên và lời gọi bộ giải mã mặc định. | 1489–1520 | Đúng | Giữ |
| C12 | Mô tả phép gán giá trị không dấu vào trường gốc theo các độ lệch đã tính. | Hàm chuyển đổi trả số không dấu nhưng tại 1518, kết quả được ép sang long có dấu trước phép gán. Phần mô tả cách tính vị trí và độ dài có căn cứ. | 1489–1520 | Sai | Giữ |
| C13 | Sao chép cơ sở dữ liệu cookie của Chrome đến tệp tạm đã nêu. | Dòng 713–714 xác nhận nguồn và đích, dòng 720 thực hiện sao chép. | 713–744 | Đúng | Giữ |
| C14 | Đọc bảng cookie và khẳng định đã ghi các trường vừa chọn ra tệp. | Đoạn 720–728 xác nhận bản sao và bảng. Dòng 729 mở bộ ghi, 732–739 truy xuất trường. Trong phần trích đến 744 chưa thấy lời ghi nối các trường với bộ ghi. | 713–744 | Thiếu căn cứ | Giữ |
| C15 | Đọc tên bộ xử lý từ registry. | Dòng 1135–1138 mở khóa và đọc giá trị tên bộ xử lý. | 1133–1163 | Đúng | Giữ |
| C16 | Truy vấn thông tin bộ điều khiển video bằng WMI. | Dòng 1148 tạo truy vấn trên lớp bộ điều khiển video. | 1133–1163 | Đúng | Giữ |
| C17 | Gán tham số chế độ nối khối cho lời gọi mở nhà cung cấp thuật toán. | Hàm bao nhận ba tham số ở 419. Ở 424, lời gọi mở provider nhận tên thuật toán và nhà cung cấp. Chế độ nối khối được áp dụng ở lời gọi khác tại 430 hoặc 433. | 416–447 | Sai | Giữ |
| C18 | Đặt thuộc tính chế độ nối khối của nhà cung cấp thuật toán. | Dòng 430 và 433 có lời gọi đặt thuộc tính. Đáp án về AES cụ thể còn cần điểm gọi chọn thuật toán ở 380, ngoài đoạn dẫn của câu. | 416–447 | Đúng | Giữ |
| C19 | Gán T1539 cho luồng thu thập cookie phiên. | Hai trích dẫn liền nhau 709–730 và 731–751 xác định kho Chrome, đích sao chép, phép sao chép ở 720, thao tác đọc bảng ở 727–728 và xử lý giá trị ở 747. Bằng chứng đủ cho kỹ thuật thu thập cookie trong mã tĩnh. | 709–730, 731–751 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

aes-provider, browser-technique, cookie-error-call, cookie-handoff, cookie-helper, cookie-key-call, hardware-message, ip-message, key-import, login-key-call, native-decrypt, password-error-call, password-handoff, post-body, tag-length, webhook-config
