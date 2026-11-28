# Nhận ra dữ liệu đi vào lời gọi trong nhánh lỗi

Các thao tác xử lý lỗi có thể nằm ngay cạnh mã đọc dữ liệu hoặc truyền tệp. Nếu một hàm nhận chuỗi xây từ thuộc tính `Message` của ngoại lệ, bằng chứng đó cho biết nguồn đối số. Để kết luận dữ liệu thu thập được gửi ra ngoài, cần lần theo một đối số mang dữ liệu thu thập đến thao tác truyền tương ứng.

## Cách demo trước lớp

1. Trên Windows đã dựng lab, mở PowerShell tại thư mục gốc và chạy `.\scripts\Start-Web.ps1`. Trình duyệt kết nối `http://127.0.0.1:4180`. Chọn Mercurial, bấm **Chạy điều tra**, theo dõi **Nhật ký** và ghi mã lượt. [Dựng lab cho thành viên mới](TEAM_SETUP.md)
2. Trong **Bản đồ chứng cứ**, mở **Nhánh xử lý lỗi** nếu VM đã trả một vị trí đủ căn cứ. Mở từng trích dẫn, đối chiếu tên biến ở khai báo `catch` với biến có thuộc tính `Message` trong đối số. Nếu Qwen giữ câu, bấm **Mở C… trong báo cáo**. Một lời gọi khác trong cùng nhánh có thể dùng một đối số hoàn toàn khác.
3. Trong **Nhận định**, mở **Vì sao báo cáo đưa ra verdict này?**. Các câu chỉ xác nhận đối số từ nhánh lỗi được giữ trong báo cáo. Ba vai trò thu thập dữ liệu nhạy cảm, truyền ra ngoài và nối dữ liệu tới bên gửi phải có chứng cứ riêng.
4. Vào **Đánh giá → Mercurial → Đối chiếu nhánh lỗi và các mục bị bỏ sót** để xem độ phủ trên toàn mẫu, chi phí và kết quả chấm lại khi bỏ riêng các câu mô tả nhánh lỗi. Các mã lượt trên máy phân tích dẫn về nguồn tương ứng. Khi hoàn tất, bấm **Tắt lab**.

## Cách xây và kiểm tra

VM dùng ILSpy để đọc mẫu .NET và tree-sitter để nhận dạng câu lệnh trong một thân hàm có cú pháp hoàn chỉnh. Bộ trích kiểm vị trí khai báo biến ngoại lệ, phạm vi của khối, vị trí lời gọi, số đối số và biểu thức tạo đối số. Phép kiểm chấp nhận `err.Message` hoặc biểu thức ghép nó với ký tự phân cách. Nó bỏ qua biểu thức ghép thêm biến khác, truyền tham chiếu, đổi biến trước điểm gọi, filter và lời gọi ở khối lồng. Nhật ký lưu các khoảng dòng và mã băm đầu ra.

Máy thật kiểm lại mã mẫu, mã kết quả và các dòng VM đã chuyển trước khi cho Qwen duyệt câu. Một nhận định về đối số lỗi chỉ được đánh dấu dùng làm ngữ cảnh khi văn bản, nguồn và toàn bộ trích dẫn khớp nhận định do bộ phân tích tạo. Bộ tổng hợp verdict nhận các câu hành vi còn đủ điều kiện. Các câu khác do Qwen tự viết vẫn cần được đối chiếu riêng. [Bộ trích trong VM](../vm_tools/catch_arguments.py) · [Cách ràng buộc câu với nguồn](../stealer_agent/operation_assertions.py)

Phép đo dùng mẫu phát triển Mercurial và 21 mục tham chiếu đã công bố. Mẫu, model, cấu hình, nguồn chấm và mã lõi được khóa trước lượt mới. Đối chiếu hai lượt điều tra bao gồm ảnh hưởng của cả chuỗi chọn công cụ và sinh câu. Để đo đóng góp riêng của các câu mô tả nhánh lỗi, phép kiểm thứ hai chấm lại đúng một báo cáo sau khi bỏ các câu đó, giữ các nhận định khác cùng verdict. Một mục có chứng cứ ở câu khác vẫn được tính. [Phạm vi phép thử](../eval/adjudications/catch-argument-protocol.json)

## Hai lượt thật trên Mercurial

| Theo cách chấm đã khóa | Trước, `20261128T112458_a0bfcbd3` | Sau, `20261128T114944_9332074e` |
|---|---:|---:|
| Đúng / sai / bịa / bỏ sót theo ý | 7 / 1 / 3 / 14 | 7 / 1 / 1 / 14 |
| Precision / recall / F1 | 63,64% / 33,33% / 43,75% | 77,78% / 33,33% / 46,67% |
| Câu đúng / sai / thiếu căn cứ | 16 / 1 / 3 | 18 / 1 / 1 |
| Câu có trích dẫn | 20/20 | 20/20 |
| Gọi công cụ / thời gian | 17 / 636,63 giây | 17 / 693,97 giây |
| Verdict của agent, nhãn tham chiếu là `malicious` | suspicious | suspicious |

Trong lượt sau, agent gọi Qwen 51 lần và nhận 17 phản hồi công cụ, không có lỗi công cụ. Có ba nhận định chỉ mô tả đối số trong nhánh lỗi. C24 dẫn hai dòng 789 và 791, C25 dẫn 765 và 768, C26 dẫn 830 và 833. Cả ba được giữ trong báo cáo. Đối chiếu yêu cầu thực gửi đến Qwen khi tổng hợp verdict xác nhận ba mã câu đã được loại khỏi cả danh sách lựa chọn và nội dung đầu vào. [Biên bản lượt chạy và thao tác trình duyệt](../deliverables/real-demo-evidence/web-20261128T114944_9332074e.json)

**Câu hỏi vấn đáp.** Tại sao C12 vẫn có thể gây hiểu nhầm? Qwen tự viết thêm một câu dựa trên khoảng dòng 803–834 và chọn câu này cho vai trò truyền ra ngoài. Điểm gọi ở dòng 833 chỉ chứng minh đối số đến từ ngoại lệ. Ở C11, tên và đường dẫn tệp xuất hiện tại điểm bàn giao, nhưng Qwen đã dùng câu cho cả vai trò gửi và nối dữ liệu với nơi gửi. Những đoạn mã cùng lọt vào một trích dẫn rộng cần được kiểm từng thao tác. Trong **Nhận định → Vì sao báo cáo đưa ra verdict này?**, bấm **Kiểm tra trên bản đồ**. Tuyến tới bước gửi của lượt này có **0/6 đường nối đủ chứng cứ**. Từ mắt xích được chọn có thể mở **Hỏi tiếp về đường nối này**. [Nhãn và lý do theo từng câu](../eval/adjudications/transfer-live-20261128T114944_9332074e.json)

**Các mục bỏ sót.** Trong 14 mục thiếu của lượt sau, có 5 mục thiếu dòng ở đầu ra VM, 2 mục đã truy xuất nhưng chưa đưa đủ dòng vào các yêu cầu tạo nhận định, 1 mục có dòng nằm ở nhiều yêu cầu, và 6 mục đã có đủ dòng trong cùng một yêu cầu. Ba mục mới được tính, đồng thời ba mục từng đúng biến mất. Vì vậy recall giữ ở 7/21. [Đối chiếu hai báo cáo](../deliverables/real-demo-evidence/catch-argument-study.json)

### Hai lần chấm lại sau thí nghiệm

1. Khi ẩn C24–C26 trong chính báo cáo sau, còn 6/21 mục và F1 41,38%. Khi giữ ba câu, kết quả là 7/21 và F1 46,67%. Chỉ mục `cookie-error-call` phụ thuộc riêng vào ba câu này. Một câu khác đã nhắc đến lời gọi ở nhánh lỗi mật khẩu.
2. Một số nhãn kế thừa chỉ tính chỉ số cột cho câu nêu rõ cả tên bảng và chỉ số. Nhóm kiểm lại hai lượt theo cùng quy tắc, đối chiếu nguyên văn câu, mã băm đầu ra và tọa độ của đúng bảng. Lượt trước vẫn đạt 7/21 và F1 43,75%. Lượt sau đạt 8/21, precision 80%, recall 38,10%, F1 51,61%. Chênh lệch giữa 7 và 8 đến từ sửa cách chấm trên cùng báo cáo. Bảng phía trên giữ kết quả theo quy tắc đã khóa. [Mã tái tính hai phép đo](../eval/catch_argument_study.py)

### Đối chứng trên chương trình sạch

Trước khi quét, nhóm chọn năm tệp theo thứ tự tên từ danh sách sạch giữ riêng có chữ ký Microsoft hợp lệ và SHA-256 khớp. Với bốn tệp, ILSpy và hai truy vấn hoàn tất. Số khớp cho `.Message` và `catch (` lần lượt là AddInProcess 0/0, AddInProcess32 0/0, AddInUtil 3/4 và aspnet_compiler 3/2. Trong các vùng nguồn công cụ trả về, bộ phân tích xác minh được **0 vị trí** thỏa điều kiện đối số. Với AppLaunch, công cụ không nhận diện được PE .NET nên hàng này để trống số đo. Phép thử chỉ đo bộ trích trên vùng nguồn đã đọc. Để đo FPR verdict phải chạy trọn agent trên các mẫu sạch có nhãn. [Biên bản năm tệp](../deliverables/real-demo-evidence/catch-clean-controls.json)

Từ thư mục gốc, chạy hai lệnh sau để tính lại từ dữ liệu công bố. Trên máy giữ nhật ký gốc, thêm `--replay` vào từng lệnh để kiểm với các sự kiện và mã băm riêng.

```powershell
.\.venv\Scripts\python.exe -m eval.catch_argument_study
.\.venv\Scripts\python.exe -m eval.catch_clean_controls
```
