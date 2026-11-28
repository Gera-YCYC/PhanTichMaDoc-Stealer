# Đối chiếu từng nhận định

Run ID `20261127T234632_6e94cea6`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Tải tệp có đường dẫn trong biến emails_pass lên địa chỉ được ghép trong mã. | The source supplies emails_pass as an expression and builds the URI argument from the named components. | 3518–3533, 3593–3617, 3645–3669, 15, 22 | Đúng | Loại |
| C2 | Tải một tệp có tên CC lên địa chỉ được ghép trong mã. | CC is a variable supplying a path. The citation does not prove a file literally named CC. The incorrect path qualifier belongs to the upload operation. | 3518–3533, 3593–3617, 3645–3669, 15, 22 | Thiếu căn cứ | Loại |
| C3 | Tải tệp ảnh chụp màn hình qua WebClient. | The call uploads the path_screenshot expression. This excerpt does not establish the actual contents of the file as a screenshot. | 3520–3535, 3671–3695, 15, 22 | Thiếu căn cứ | Giữ |
| C4 | Giải mã ASCII phản hồi upload rồi gán vào Fileuri4. | The bytes returned from the upload are decoded as ASCII and assigned to Fileuri4. | 3520–3535, 3671–3695, 15, 22 | Đúng | Giữ |
| C5 | Gửi nội dung tệp có đường dẫn trong info_pc tới địa chỉ được ghép. | The file supplied through info_pc is uploaded to the composed address. The description identifies outgoing file contents and makes no claim of plaintext recovery. | 3514–3529, 3619–3643, 15, 22 | Đúng | Giữ |
| C6 | Giải mã phản hồi của lượt gửi tệp thông tin và gán vào Fileuri2. | The upload result bytes are explicitly decoded and assigned to Fileuri2. | 3514–3529, 3619–3643, 15, 22 | Đúng | Giữ |
| C7 | Tải tệp được chỉ bởi biến Passwords. | The upload uses the Passwords variable as the local path and the concatenated destination expression. | 3512–3527, 3567–3591, 15, 22 | Đúng | Loại |
| C8 | Giải mã ASCII phần phản hồi và gán vào Fileuri. | The returned response is ASCII decoded and assigned to Fileuri. | 3512–3527, 3567–3591, 15, 22 | Đúng | Giữ |
| C9 | Đọc Login Data của Opera để lấy thông tin đăng nhập. | The Opera path is opened and the logins fields are actually read. The sentence does not name each field separately. | 1040–1071 | Đúng | Giữ |
| C10 | Giải mã trường mật khẩu bằng helper sau khi chuyển đổi từ byte. | Encoding.Default.GetBytes converts the selected field to bytes before the custom helper. The claimed direction from bytes is contradicted. No body here verifies decryption. | 1040–1071 | Sai | Giữ |
| C11 | Đọc Login Data của Chrome để lấy thông tin đăng nhập. | The Chrome Login Data path and field reads are visible. No separate credit for a specific field name absent from the sentence. | 1088–1119 | Đúng | Giữ |
| C12 | Giải mã mật khẩu rồi tạo đối tượng Account với thông tin đã giải mã. | Account construction is explicit. The two decrypted-result clauses both rely on the unseen custom helper body and are the same unsupported proposition. | 1088–1119 | Thiếu căn cứ | Loại |
| C13 | Đọc giá trị SMTP Server từ cấu hình dưới dạng mảng byte. | GetValue and the byte-array cast are in the quoted source. This identifies a stored configuration value, not a real SMTP connection. | 4841–4870 | Đúng | Giữ |
| C14 | Đổi byte sang chuỗi rồi gán vào URL của đối tượng tài khoản. | The recovered account and URL assignment contain the encoding operation on bytes. | 4841–4870 | Đúng | Giữ |
| C15 | Ghi thông tin tài khoản trình duyệt vào một tệp có tên Passwords. | The code writes the enumerated browser account fields with a StreamWriter. The target is a path variable and no quoted literal basename is demonstrated. | 3473–3500 | Thiếu căn cứ | Loại |
| C16 | Ghi đè thông tin hệ thống vào một tệp có tên info_pc. | The shown File.WriteAllText call overwrites with an empty string. It does not write system information and the path variable does not establish a literal filename. | 3473–3500 | Sai | Giữ |
| C17 | Gọi upload gián tiếp và lấy đường dẫn từ thư mục hiện hành. | The WebClient late-bound upload call is visible. A variable named current does not prove a path originating in the process current directory. | 4240–4267 | Thiếu căn cứ | Giữ |
| C18 | Giải mã ASCII phản hồi sau lời gọi upload gián tiếp. | The returned object is converted to bytes then ASCII-decoded at the first late-bound site. | 4240–4267 | Đúng | Giữ |
| C19 | Gọi upload gián tiếp để gửi tệp hệ thống cục bộ đến máy chủ từ xa. | The second late-bound local-file upload call is real. The actual destination host or remote server is not resolved by this citation. | 4289–4320 | Thiếu căn cứ | Giữ |
| C20 | Dùng bộ giải mã ASCII để lấy nội dung tệp đã tải lên từ phần phản hồi. | The ASCII decoder acts on the upload response. It does not retrieve the uploaded file contents. The following clause correctly describes the response conversion. | 4289–4320 | Sai | Giữ |
| C21 | Gọi UploadFile với địa chỉ ghép và đường dẫn trong emails_pass. | The imported/bound client and cited call establish the stated operand roles at this upload site. | 15, 3600, 3603 | Đúng | Giữ |
| C22 | Giải mã ASCII byte phản hồi của lượt upload tại vị trí emails_pass. | The documented upload result is explicitly supplied to the ASCII decoder at this site. | 15, 3600, 3603, 22, 3604 | Đúng | Giữ |
| C23 | Gọi UploadFile với địa chỉ ghép và đường dẫn trong Passwords. | The imported/bound client and cited call establish the stated operand roles at this upload site. | 15, 3574, 3577 | Đúng | Giữ |
| C24 | Giải mã ASCII byte phản hồi của lượt upload tại vị trí Passwords. | The documented upload result is explicitly supplied to the ASCII decoder at this site. | 15, 3574, 3577, 22, 3578 | Đúng | Giữ |
| C25 | Gọi UploadFile với địa chỉ ghép và đường dẫn trong path_screenshot. | The imported/bound client and cited call establish the stated operand roles at this upload site. | 15, 3678, 3681 | Đúng | Giữ |
| C26 | Giải mã ASCII byte phản hồi của lượt upload tại vị trí path_screenshot. | The documented upload result is explicitly supplied to the ASCII decoder at this site. | 15, 3678, 3681, 22, 3682 | Đúng | Giữ |
| C27 | Gọi UploadFile với địa chỉ ghép và đường dẫn trong info_pc. | The imported/bound client and cited call establish the stated operand roles at this upload site. | 15, 3626, 3629 | Đúng | Giữ |
| C28 | Giải mã ASCII byte phản hồi của lượt upload tại vị trí info_pc. | The documented upload result is explicitly supplied to the ASCII decoder at this site. | 15, 3626, 3629, 22, 3630 | Đúng | Giữ |
| C29 | Gọi UploadFile với địa chỉ ghép và đường dẫn trong CC. | The imported/bound client and cited call establish the stated operand roles at this upload site. | 15, 3652, 3655 | Đúng | Giữ |
| C30 | Giải mã ASCII byte phản hồi của lượt upload tại vị trí CC. | The documented upload result is explicitly supplied to the ASCII decoder at this site. | 15, 3652, 3655, 22, 3656 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

browser-attack, capture, chrome-account, chrome-decrypt-call, chrome-origin_url, chrome-password_value, chrome-table, chrome-username_value, config-field, config-split, decrypt-declaration, dpapi, late-one-upload, late-two-upload, logs-fragment, opera-account, opera-decrypt-call, opera-origin_url, opera-password_value, opera-table, opera-username_value, save-capture, screen-attack, screen-fragment, self-read, utf8
