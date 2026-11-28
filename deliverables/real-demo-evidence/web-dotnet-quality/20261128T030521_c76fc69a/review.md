# Đối chiếu từng nhận định

Run ID `20261128T030521_c76fc69a`. Cột thứ hai diễn ý câu của agent. Bảng giữ cả những nhận định mà bộ tự duyệt đã loại. Tọa độ là số dòng trong kết quả công cụ của mẫu.

| ID | Agent nói | Đối chiếu mã nguồn | Dòng đối chiếu | Nhãn | Tự duyệt |
|---|---|---|---|---|---|
| C1 | Dùng biểu thức đường dẫn của tệp và lưu byte phản hồi. | Dòng 3655 truyền biến đường dẫn vào lời gọi và gán giá trị trả về cho mảng. | 3516–3531, 3645–3669, 15, 22 | Đúng | Giữ |
| C2 | Đọc nội dung phản hồi dưới dạng ASCII và gán kết quả. | Dòng 3655–3656 cho thấy mảng trả về, bộ giải mã và biến nhận kết quả. | 3516–3531, 3645–3669, 15, 22 | Đúng | Giữ |
| C3 | Truyền tệp do biến đường dẫn chỉ định tới đích ghép từ hai thành phần. | Tại dòng 3603, hai đối số đúng vai trò mà câu mô tả. | 3518–3533, 3593–3617, 15, 22 | Đúng | Loại |
| C4 | Giải mã mảng byte phản hồi và gán vào biến kết quả. | Tại dòng 3603–3604, mảng nhận kết quả rồi được chuyển thành văn bản ASCII. | 3518–3533, 3593–3617, 15, 22 | Đúng | Giữ |
| C5 | Gọi tệp được gửi là ảnh màn hình và mô tả cách ghép đích. | Đoạn trích cho thấy biến đường dẫn được truyền vào lời gọi. Nội dung ảnh chưa được chứng minh. Dòng 3677 và 3681 xác nhận phần ghép đích. | 3520–3535, 3671–3695, 15, 22 | Thiếu căn cứ | Loại |
| C6 | Giải mã phản hồi của lời gọi tại vị trí có đường dẫn ảnh. | Dòng 3681 và 3682 nối mảng phản hồi với lời gọi giải mã ASCII và biến nhận. | 3520–3535, 3671–3695, 15, 22 | Đúng | Giữ |
| C7 | Dùng đường dẫn tệp do biến cấu hình chỉ định và lưu kết quả trả về. | Dòng 3629 cho thấy cả đối số tệp và đích, sau đó gán lại kết quả cho mảng. | 3514–3529, 3619–3643, 15, 22 | Đúng | Giữ |
| C8 | Chuyển mảng phản hồi thành văn bản ASCII. | Dòng 3629–3630 xác nhận nguồn mảng và phép gán vào biến đã nêu. | 3514–3529, 3619–3643, 15, 22 | Đúng | Giữ |
| C9 | Gọi phương thức qua liên kết muộn và suy ra đường dẫn thuộc thư mục hiện hành. | Tên phương thức và đối tượng hiện ở 4244–4253. Dòng 4243 lấy phần tử hiện tại của trình duyệt tập hợp. Tên biến chưa xác định thư mục làm việc của tiến trình. | 4240–4267 | Thiếu căn cứ | Giữ |
| C10 | Giải mã phản hồi của lời gọi gián tiếp thứ nhất. | Lời gọi, phép chuyển thành byte và bộ giải mã ASCII xuất hiện ở 4253, 4262 và 4263. | 4240–4267 | Đúng | Giữ |
| C11 | Nêu lời gọi gián tiếp thứ hai và suy đích là máy chủ từ xa. | Dòng 4297–4306 xác nhận đối tượng, phương thức và biến đích. Trích dẫn chưa giải được địa chỉ hay vị trí mạng của máy nhận. | 4289–4320 | Thiếu căn cứ | Giữ |
| C12 | Liệt kê tệp ảnh trong thư mục tài liệu rồi nêu việc gửi lên máy chủ từ xa. | Dòng 4293–4296 cho thấy thư mục, bộ lọc và phần tử được chọn. Ở 4302–4306 đích còn là biến. Chưa có giá trị đích để xác nhận máy chủ từ xa. | 4289–4320 | Thiếu căn cứ | Giữ |
| C13 | Đọc một vùng byte thành văn bản và gán trường kiểu của bảng. | Dòng 2748 dùng bộ mã mặc định, khoảng byte và phần tử đích mà câu mô tả. | 2735–2766 | Đúng | Giữ |
| C14 | Đọc vùng byte theo Unicode và gán trường tên của bảng. | Dòng 2764 có bộ mã Unicode, các toán hạng tính vị trí và độ dài, cùng phép gán trường tên. | 2735–2766 | Đúng | Loại |
| C15 | Chọn bộ giải mã theo giá trị cấu hình mã hóa. | Các nhánh ở 2746–2756 lần lượt chọn bộ mã mặc định, Unicode hoặc BigEndianUnicode. | 2745–2776 | Đúng | Giữ |
| C16 | Chuyển đầu vào thành byte, gọi API bảo vệ dữ liệu và chuyển kết quả sang UTF-8. | Dòng 4098–4100 nối liền ba thao tác. Đây là vị trí khác với mục DPAPI ở dòng 880 trong đáp án. | 4084–4114 | Đúng | Giữ |
| C17 | Gọi Unprotect để giải mã mảng byte ở một hàm khác. | Lời gọi có đối số mảng xuất hiện trực tiếp tại dòng 4890, khác vị trí DPAPI đã chốt. | 4875–4906 | Đúng | Giữ |
| C18 | Xác định biểu thức đích và đối số đường dẫn cục bộ trong lời gọi tải tệp. | Tên phương thức và hai biểu thức tại dòng 3681 khớp với các vai trò được nêu. | 15, 3678, 3681 | Đúng | Giữ |
| C19 | Chuyển mảng byte phản hồi thành văn bản ASCII. | Đối chiếu dòng 3681 và 3682. Mảng trả về của lời gọi là đầu vào của bộ giải mã. | 15, 3678, 3681, 22, 3682 | Đúng | Giữ |
| C20 | Chuyển mảng byte phản hồi thành văn bản ASCII. | Đối chiếu dòng 3655 và 3656. Mảng trả về của lời gọi là đầu vào của bộ giải mã. | 15, 3652, 3655, 22, 3656 | Đúng | Giữ |
| C21 | Xác định biểu thức đích và đối số đường dẫn cục bộ trong lời gọi tải tệp. | Tên phương thức và hai biểu thức tại dòng 3655 khớp với các vai trò được nêu. | 15, 3652, 3655 | Đúng | Giữ |
| C22 | Xác định biểu thức đích và đối số đường dẫn cục bộ trong lời gọi tải tệp. | Tên phương thức và hai biểu thức tại dòng 3603 khớp với các vai trò được nêu. | 15, 3600, 3603 | Đúng | Giữ |
| C23 | Chuyển mảng byte phản hồi thành văn bản ASCII. | Đối chiếu dòng 3603 và 3604. Mảng trả về của lời gọi là đầu vào của bộ giải mã. | 15, 3600, 3603, 22, 3604 | Đúng | Giữ |
| C24 | Chuyển mảng byte phản hồi thành văn bản ASCII. | Đối chiếu dòng 3577 và 3578. Mảng trả về của lời gọi là đầu vào của bộ giải mã. | 15, 3574, 3577, 22, 3578 | Đúng | Giữ |
| C25 | Xác định biểu thức đích và đối số đường dẫn cục bộ trong lời gọi tải tệp. | Tên phương thức và hai biểu thức tại dòng 3577 khớp với các vai trò được nêu. | 15, 3574, 3577 | Đúng | Giữ |
| C26 | Chuyển mảng byte phản hồi thành văn bản ASCII. | Đối chiếu dòng 3629 và 3630. Mảng trả về của lời gọi là đầu vào của bộ giải mã. | 15, 3626, 3629, 22, 3630 | Đúng | Giữ |
| C27 | Xác định biểu thức đích và đối số đường dẫn cục bộ trong lời gọi tải tệp. | Tên phương thức và hai biểu thức tại dòng 3629 khớp với các vai trò được nêu. | 15, 3626, 3629 | Đúng | Giữ |

## Mục bị bỏ sót trên đáp án đã chốt

browser-attack, capture, chrome-account, chrome-decrypt-call, chrome-open, chrome-origin_url, chrome-password_value, chrome-table, chrome-username_value, config-field, config-split, decrypt-declaration, dpapi, late-one-upload, late-two-ascii, late-two-upload, logs-fragment, opera-account, opera-decrypt-call, opera-open, opera-origin_url, opera-password_value, opera-table, opera-username_value, save-capture, screen-attack, screen-fragment, self-read, utf8
