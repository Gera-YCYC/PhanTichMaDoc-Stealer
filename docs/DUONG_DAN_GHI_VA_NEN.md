# Đích ghi có nằm trong thư mục nén không?

Trong lượt Python `20261128T071542_c577c28e`, agent tìm được bằng chứng tĩnh cho thấy một lệnh ghi tạo đường dẫn dưới thư mục đầu vào của lệnh nén. Một lệnh ghi khác trong cùng hàm dùng thư mục bên cạnh. Đường nối **Ghi ra tệp → Tạo bản nén** vẫn màu vàng. Việc hai biểu thức đường dẫn khớp nhau chưa chứng minh được tệp còn ở đó, với nội dung cũ, khi lệnh nén chạy.

## Chạy cho giảng viên xem

1. Trên máy Windows đã dựng lab, mở PowerShell tại thư mục có `agent_react.py` và chạy `.\scripts\Start-Web.ps1`. Mở **http://127.0.0.1:4180**. Thanh đầu trang phải báo **Ollama sẵn sàng** và **VM cô lập**. Trình duyệt và Qwen3 8B chạy trên máy thật. VM giữ mẫu và chạy các công cụ đọc tĩnh. [Dựng lab trên máy thành viên](TEAM_SETUP.md)
2. Chọn `public_python2024.bin` và bấm **Chạy điều tra**. Trong **Nhật ký**, theo dõi mã lượt mới, công cụ vừa gọi và kết quả trả về. Trong lượt dẫn ở trên, pycdc gặp lỗi, agent chuyển sang pycdas rồi đọc các đặc trưng Python đã khôi phục.
3. Mở **Bản đồ chứng cứ → Ghi ra tệp → Tạo bản nén → Đối chiếu đích ghi với thư mục nén**. Mở một trích dẫn để xem dòng được đánh dấu và SHA-256 của nguồn. Mỗi bản đồ gắn với kết quả của chính lượt được chọn.
4. Trong **Hỏi đáp**, nhập “Đích ghi tệp có nằm trong thư mục nén và tệp còn nguyên lúc nén không?”. Khi còn thiếu bằng chứng, Qwen chọn một phép tìm, VM tra cứu và ghi nhật ký. Với lượt đã đo, kết quả có 8 vị trí cần xem tiếp. Số lần xuất hiện của thao tác sửa hoặc xóa không cho biết tệp nào thực sự bị thay đổi. Khi cần minh họa truy vấn trực tiếp, hãy dùng lượt vừa chạy trong phiên VM hiện tại.
5. Trong **Đánh giá**, chọn PythonStealer, mở **Đích ghi và thư mục nén · các lượt Python** để xem cả chi phí lẫn điểm số. **YARA** cho biết luật và tập đã quét. Khi xong, bấm **Tắt lab** và đợi PowerShell xác nhận VM cùng Ollama đã dừng.

## Bằng chứng agent thu được

| Câu hỏi | Kết quả ở lượt đã đo |
|---|---|
| Cái gì làm agent gọi thêm công cụ? | Hai đầu ghi và nén đã xuất hiện, quan hệ giữa chúng còn mở. Ở bước 7, phép tìm đầu tiên chưa trả được bằng chứng đường dẫn. Ở bước 8, kết quả tìm khác kích hoạt bộ kiểm tra cú pháp trong VM. |
| VM xác minh phần nào? | Xét 16 giá trị tên thư mục con có thể nhận trong đoạn mã. Đích ghi nằm bên dưới thư mục nén cho cả 16. Có 38 dòng hỗ trợ, chia thành 13 khoảng mở được trên web. |
| Người đọc kiểm thế nào? | Từ đường nối mở các điểm định nghĩa và sử dụng. Kiểm lời gọi bên ghi và đối số đường dẫn của lệnh nén. Nhận định C31 chỉ mô tả dữ liệu từ kết quả một hàm cục bộ đến đối số ghi. |
| Còn thiếu gì? | Nguồn gốc nhạy cảm của giá trị, sự tồn tại và nội dung của tệp lúc nén, và việc chuyển nội dung đó đến bên nhận. Phân tích tĩnh cũng không xác nhận đã có lưu lượng mạng. |

Bộ kiểm dựa vào nút cú pháp và chứng cứ công cụ có kiểu. Nó đối chiếu tên, phạm vi biến, đối số ở vị trí gọi, thư mục gốc và từng thành phần đường dẫn. Gặp biến bị gán lại, tên động ngoài tập hữu hạn, thư mục kế bên hoặc hai câu lệnh trên cùng dòng gây nhập nhằng, bộ kiểm bỏ qua kết luận. Lớp điều phối kiểm hash mẫu, hash đầu ra, mã chứng cứ và đủ dòng còn đọc được sau khi lọc trước khi đưa kết quả vào bản đồ. Đây là quan hệ đường dẫn trong mã, chưa tính trạng thái hệ thống tệp khi chạy.

## Điểm của hai báo cáo trên cùng mẫu

| Chỉ số | Lượt trước `053257` | Lượt có đối chiếu `071542` |
|---|---:|---:|
| Mục đúng / mục tham chiếu | 21/36 | 19/36 |
| Precision | 95,45% | 100% |
| Recall | 58,33% | 52,78% |
| F1 | 72,41% | 69,09% |
| Verdict | suspicious | suspicious |
| Gọi công cụ / lỗi | 17 / 1 | 17 / 1 |
| Gọi model | 40 | 42 |
| Thời gian | 434,27 giây | 531,20 giây |

Hai lượt đều giữ 31 câu. Lượt mới mất **A09** (liên hệ giữa trường được chọn và đối số xử lý) và **A26** (đường dẫn do hàm nén trả về đi vào tham số đính kèm). C31 có dẫn chứng nhưng không nêu loại dữ liệu nên chưa khớp mục tham chiếu về thông tin đăng nhập. Precision tăng vì mục sai ở lượt trước đã mất, trong khi recall và F1 giảm. Cả hai verdict đều thấp hơn nhãn độc của mẫu. Hai lần chạy đầu-cuối chưa đủ để quy chênh lệch điểm cho riêng bộ kiểm đường dẫn. [Phiếu chấm ba câu thay đổi](../eval/adjudications/transfer-live-20261128T071542_c577c28e.json) · [Kết quả toàn báo cáo](../deliverables/real-demo-evidence/transfer-live-20261128T071542_c577c28e.json)

Lượt `071542` có một lần hỏi bị chuyển nhầm sang liên kết nén–thông điệp. Bản sửa phân biệt “thư mục” với “thư”. Khi nạp lại mã web và hỏi lại cùng câu trên cùng VM, truy vấn đến đúng liên kết ghi–nén và mở được 13 khoảng chứng cứ ở chiều rộng 390 px. Nhật ký lưu cả hai lần hỏi. YARA 4.5.4 khớp luật trong tập phát triển của mẫu này. Kết quả một mẫu chưa cho phép tính TPR trên tập giữ riêng. [Biên bản lượt chạy và hỏi đáp](../deliverables/real-demo-evidence/web-20261128T071542_c577c28e.json)

Sau lượt đầu-cuối, bộ kiểm VM được siết điều kiện cho lời gọi nén và các câu lệnh chung dòng. Khi chạy bản sửa trên đúng nguồn, đúng hash và đúng các cửa sổ mà agent đã đọc, kết quả ở các bước yêu cầu kiểm đường dẫn trùng với nhật ký gốc. Trong sáu cửa sổ tìm liên kết của mỗi lượt, ba cửa sổ chứa vị trí đủ để bộ kiểm mới tìm thấy quan hệ. Với lượt cũ, đây là phép thử hồi cứu. [Tọa độ, hash và biên bản đối chiếu](../deliverables/real-demo-evidence/staging-path-python.json)

## Tái lập kết quả

Lượt lặp `20261128T073934_730537f9` bắt đầu từ **Chạy điều tra** sau khi khởi động lại cả lab. Toàn bộ hash mã lõi khớp phiên bản đã bàn giao. Sau 408,65 giây, 42 lượt gọi Qwen, 17 lượt gọi công cụ và một lỗi dịch ngược, agent lại tìm được bằng chứng đường dẫn ở bước 8. Bản đồ vẫn để liên kết ở mức cần kiểm tra thêm. Trong câu hỏi tiếp theo, VM khớp 8 vị trí và trả về hai vị trí đã xếp hạng. Người dùng mở được cả hai dòng 251, 153 ở phần **Vị trí VM vừa tìm**, bên cạnh 13 khoảng nguồn của bản đồ. Việc tìm thấy thao tác xóa ở một dòng chưa chứng minh nó xóa đúng tệp đang điều tra. [Biên bản VM và thao tác trình duyệt](../deliverables/real-demo-evidence/web-20261128T073934_730537f9.json)

Lần lặp giữ 32 nhận định. Có 31 câu khớp với lượt trước về nội dung và trích dẫn sau khi chuẩn hóa mã lượt. Câu còn lại giúp khôi phục mục A26. Điểm toàn báo cáo là **20/36**, precision **100%**, recall **55,56%**, F1 **71,43%**, verdict **suspicious**. Nhãn đích là độc. Ba lượt trong mục Đánh giá dùng hai phiên bản bộ kiểm và một lượt chưa có tính năng, nên chưa phải phép đo ổn định ba lần trên cùng phiên bản. [Phiếu chấm và điểm lượt lặp](../deliverables/real-demo-evidence/transfer-live-20261128T073934_730537f9.json)

Từ gốc dự án, lệnh đầu đối chiếu các biên bản công khai, chạy được cả khi lab tắt. Lệnh thứ hai kiểm lại bằng nhật ký riêng và kết quả mở trích dẫn của trình duyệt trên máy đã đo. Lệnh cuối cần VM đang chạy và còn giữ hai hồ sơ gốc.

```powershell
.\.venv\Scripts\python.exe -m eval.staging_path_audit
.\.venv\Scripts\python.exe -m eval.staging_path_audit --replay
.\.venv\Scripts\python.exe -m eval.staging_path_audit --vm
```

Các phép kiểm phần mềm dùng dữ liệu tài liệu họp vô hại để thử đường dẫn hợp lệ, thư mục kế bên và biến đổi tên. Số liệu ở hai bảng trên lấy từ agent, Qwen và VM thật. [Các phép kiểm hồi quy](../tests/test_staging_path.py)

### Ghi bằng chứng thao tác trên một máy khác

Thành viên có thể tự bấm theo các bước demo bên trên. Để ghi lại tọa độ đã mở từ một lượt Python mới, repo còn có phép kiểm tự động bằng Chromium. Chạy sau khi lượt điều tra kết thúc, khi web, Ollama và VM vẫn còn hoạt động. Cần Node.js và Chromium. Trong PowerShell bên dưới, điền đường dẫn Chromium đã cài và mã lượt trên màn hình. Phần phụ thuộc dành riêng cho phép kiểm giao diện.

```powershell
npm install --prefix ./private/web-check playwright-core@1.58.2
$env:NODE_PATH = (Resolve-Path ./private/web-check/node_modules).Path
$env:LAB_CHROMIUM = 'C:\duong-dan-den-chromium\chrome.exe'
node scripts/verify_web_staging.mjs MA_LUOT_PYTHON
.\.venv\Scripts\python.exe scripts/export_investigation_receipt.py --run MA_LUOT_PYTHON
```

Phép kiểm mở bản đồ ở chiều rộng 390 px, bấm từng trích dẫn, đặt câu hỏi thật rồi mở riêng các dòng VM vừa trả về. Biên bản cục bộ nằm ở `evidence/local/staging-MA_LUOT_PYTHON.json`. Bản xuất ở `deliverables/real-demo-evidence/` chỉ chứa số đo, tọa độ và mã băm. Một lượt thiếu chứng cứ làm phép kiểm dừng tại bước tương ứng.
