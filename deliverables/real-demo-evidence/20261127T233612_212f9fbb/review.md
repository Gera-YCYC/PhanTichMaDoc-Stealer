# Đối chiếu từng nhận định

Run ID `20261127T233612_212f9fbb`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Tạo tệp ZIP của thư mục Browser trong thư mục tạm. | make_archive uses zip format and the temporary Browser directory; its returned archive path is Browser.zip. No contents or runtime success asserted. | 313–328, 82–113, 276–286, 10, 14 | Đúng | Giữ |
| C2 | Gửi email qua SMTP có xác thực và đính kèm tệp ZIP. | Archive body, return value, caller and complete send_email body are supplied. The archive path is read, attached, serialized and passed to sendmail after login. Static capability, not successful delivery. | 313–328, 82–113, 276–286, 10, 14 | Đúng | Giữ |
| C3 | Dùng một hostname cụ thể làm máy chủ SMTP. | The exact SMTP hostname literal is assigned and used by the SMTP constructor. This is a configured destination candidate, not confirmed malicious infrastructure or observed traffic. | 313–328, 82–113, 276–286, 10, 14 | Đúng | Giữ |
| C4 | Chép Login Data của trình duyệt vào thư mục tạm. | The source constructs the Login Data path then copies it to the user temporary login_db path. | 289–304, 134–154, 69–75, 10, 9 | Đúng | Giữ |
| C5 | Mở kết nối SQLite tới bản sao Login Data. | The database connection receives the copy destination as its argument. | 289–304, 134–154, 69–75, 10, 9 | Đúng | Giữ |
| C6 | Chép cơ sở dữ liệu lịch sử web vào thư mục tạm. | The history helper constructs the History database path and calls shutil.copy at line 192. | 291–306, 186–207, 10, 9 | Đúng | Giữ |
| C7 | Mở SQLite trên bản sao cơ sở dữ liệu lịch sử. | The history helper opens the copy destination with sqlite3.connect at line 193. | 291–306, 186–207, 10, 9 | Đúng | Giữ |
| C8 | Gọi API DPAPI trên biến khóa chính. | The implementation calls the imported CryptUnprotectData with master_key. The assertion does not describe the five-byte slice required by A03. | 288–301, 52–66, 11, 8 | Đúng | Giữ |
| C9 | Giải mã Base64 trường encrypted_key trong Local State. | The encoded key accessed under os_crypt is the operand of the Base64 decoder. | 288–301, 52–66, 11, 8 | Đúng | Giữ |
| C10 | Gọi helper của profile Default để lấy dữ liệu đăng nhập. | The submitted caller proves the helper invocation, arguments and assignment. Its implementation is absent from this claim, so the asserted collection effect is unverified here. | 293–324 | Thiếu căn cứ | Giữ |
| C11 | Truyền kết quả đăng nhập cho helper và khẳng định đích ghi là tệp văn bản. | The caller actually passes login_data and Saved_Passwords to the save helper. A comment mentions text output, but these references do not include the implementation which establishes the file write. | 293–324 | Thiếu căn cứ | Giữ |
| C12 | Ghi nội dung vào tệp theo loại dữ liệu trong thư mục tạm của trình duyệt. | The complete write helper contains the non-null guard and constructs the browser/data-type text path under the temporary directory. | 101–132, 14 | Đúng | Giữ |
| C13 | Gửi qua SMTP nội dung thư đã tuần tự hóa. | The serialized text and the use of that text in the SMTP send call are visible at lines 103 and 109. | 101–132, 14 | Đúng | Giữ |
| C14 | Truy vấn ba trường về URL, tài khoản và mật khẩu trong bảng logins. | The executed SELECT lists all three named fields and the logins table. | 142–173, 9, 140, 141 | Đúng | Giữ |
| C15 | Duyệt các dòng rồi giải mã trường mật khẩu bằng helper và khóa chính. | The loop iterates fetchall results and passes the password column and master_key to a helper. The submitted excerpts omit the body needed to establish actual cryptographic decryption. | 142–173, 9, 140, 141 | Thiếu căn cứ | Giữ |
| C16 | Truy vấn URL và đường dẫn tệp đích trong bảng downloads. | The cursor executes the two-column SELECT on the downloads table. | 218–249 | Đúng | Giữ |
| C17 | Chép tệp mang đường dẫn của biến login_db tới đường dẫn tạm. | The copy operands are visible. This narrower statement does not resolve the source expression to a specific browser database. | 10, 139 | Đúng | Giữ |
| C18 | Gọi SQLite connect với đường dẫn login_db tạm. | The bound sqlite3.connect call takes the temporary login_db path. | 9, 140 | Đúng | Giữ |
| C19 | Thực hiện SELECT ba trường của bảng logins. | The bound cursor executes the same logins SELECT with all declared columns. | 9, 140, 141, 142 | Đúng | Giữ |
| C20 | Gọi fetchall sau truy vấn bảng logins. | The same cursor calls fetchall after the logins SELECT. | 9, 140, 141, 142, 143 | Đúng | Giữ |
| C21 | Ghi biến content vào đường dẫn tạm được tạo từ tên trình duyệt và loại dữ liệu. | The interpolated output and write operand are visible. This two-line claim does not supply the non-null guard. | 123, 124 | Đúng | Giữ |
| C22 | Ghi biến content vào tệp văn bản tổng hợp autofill. | The destination and write operand are cited. The claim does not say append or identify the guard required by A30. | 128, 129 | Đúng | Giữ |
| C23 | Tạo ZIP với thư mục Browser tạm làm gốc dữ liệu. | The source supplies zip format, the temporary base name and Browser staging root. | 10, 279 | Đúng | Giữ |
| C24 | Gọi sendmail với các biến người gửi, người nhận và nội dung. | The SMTP receiver, sendmail call and three named expressions are present. | 14, 106, 109 | Đúng | Giữ |
| C25 | Gọi đăng nhập SMTP với hai đối số xác thực. | The SMTP receiver and its two credential argument positions are explicit. A local display suppresses sensitive literals. No successful authentication is claimed. | 14, 106, 108 | Đúng | Giữ |
| C26 | Yêu cầu STARTTLS trên kết nối SMTP. | The bound SMTP client explicitly requests STARTTLS. | 14, 106, 107 | Đúng | Giữ |
| C27 | Tạo đối tượng SMTP với biến máy chủ và cổng. | The SMTP constructor takes the configured host and port expressions. | 14, 106 | Đúng | Giữ |
| C28 | Gắn phần thân văn bản thuần vào thư nhiều phần. | The multipart message attaches MIMEText of the plain message body. | 16, 90, 94 | Đúng | Giữ |
| C29 | Gắn phần MIME vào thư. | The multipart message attaches the MIME part. | 16, 90, 102 | Đúng | Giữ |
| C30 | Chuyển thư nhiều phần thành chuỗi. | as_string is invoked on the multipart message. | 16, 90, 103 | Đúng | Giữ |
| C31 | Gọi AES-GCM decrypt với dữ liệu, khóa và nonce. | The bound cipher comes from AES GCM with this key/nonce. Its decrypt method takes the payload expression. | 12, 72, 73 | Đúng | Giữ |
| C32 | Gọi CryptUnprotectData trên biến khóa chính. | The import and call establish DPAPI with this argument. These citations do not include the prefix-removal operation. | 11, 65 | Đúng | Giữ |
| C33 | Giải mã Base64 giá trị encrypted_key trong cấu hình. | The Base64 argument contains the local_state encrypted key lookup. | 8, 63 | Đúng | Giữ |
| C34 | Đọc tệp Local State. | The file object opened at the Local State path is read. | 59, 60 | Đúng | Giữ |
| C35 | Ghi từng phần tử đã định dạng vào tệp tạm theo tên truyền vào. | The text file path uses the filename parameter and the write operand formats each item. | 271, 273 | Đúng | Giữ |
| C36 | Chép tệp lịch sử tới đường dẫn tạm. | The operands and copy call point to the same history-file copy site as C6. | 10, 192 | Đúng | Giữ |
| C37 | Mở SQLite với đường dẫn lịch sử tạm. | The SQLite call uses the same temporary history path as C7. | 9, 193 | Đúng | Giữ |
| C38 | Truy vấn URL, tiêu đề và lần truy cập cuối trong bảng lịch sử. | The history SELECT names the url, title and last-visit columns. | 9, 193, 194, 195 | Đúng | Giữ |
| C39 | Lấy các dòng kết quả của truy vấn lịch sử. | The bound history cursor calls fetchall following that SELECT. | 9, 193, 194, 195, 196 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

PY24-A03, PY24-A10, PY24-A11, PY24-A12, PY24-A13, PY24-A14, PY24-A17, PY24-A19, PY24-A28, PY24-A29, PY24-A30, PY24-A32, PY24-A33, PY24-A34
