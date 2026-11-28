# Kiểm tra cách mẫu .NET đọc cột

Một lời gọi đọc cột có thể truyền tên hoặc một số thứ tự. Ví dụ trong buổi vấn đáp, người xem có thể hỏi “Dòng nào cho thấy đây là tên trường?” rồi bấm mở nguồn. Nếu mã truyền số, cần thêm lược đồ đúng phiên bản trước khi xác định trường đó chứa gì.

## Demo trên máy nhóm

1. Trong PowerShell tại thư mục dự án, chạy `.\scripts\Start-Web.ps1` rồi mở `http://127.0.0.1:4180`. Mục trạng thái phải thấy Ollama sẵn sàng và VM cô lập. Trên máy mới, dựng môi trường theo [hướng dẫn của nhóm](TEAM_SETUP.md).
2. Chọn Gomorrah hoặc Mercurial và bấm **Chạy điều tra**. Trong **Nhật ký**, theo dõi lần agent chọn một liên kết còn thiếu rồi nhận kết quả từ công cụ. Mỗi lần bấm tạo mã lượt mới.
3. Mở **Bản đồ chứng cứ → Đọc kết quả truy vấn**. Chọn một dòng trong **Đối số đọc cột trong mã .NET**, mở các trích dẫn và so vị trí khai báo, chọn bảng, đọc cột. Giá trị chuỗi riêng được che. Nút **Mở C… trong báo cáo** xuất hiện khi quyết định của model, câu được giữ và nguồn dẫn cùng khớp với nhật ký. Nếu VM chưa trả vị trí hợp lệ, mục danh sách này sẽ trống.
4. Vào **Đánh giá**, chọn đúng mẫu .NET rồi mở **Đối chiếu cách đọc cột**. Trên máy có hồ sơ, bấm mã lượt để quay lại nguồn. Bảng điểm công khai vẫn đọc được sau khi clone, còn các trích dẫn nằm trên máy chạy lab. Kết thúc demo bằng nút **Tắt lab** khi tác vụ đã xong.

## Công cụ và cách tính

VM đọc tĩnh bản dịch ngược của ILSpy. Bộ phân tích cú pháp ghi nhận hai lời gọi trên cùng biến đọc, điều kiện tạo biến, đối số và các khoảng dòng. Phía máy thật kiểm lại mã mẫu, mã đầu ra, mã phát hiện và dòng đã nhận trước khi chuyển chứng cứ cho Qwen. Bản đồ lưu riêng vị trí công cụ nhận ra và câu được model giữ. Phép kiểm này chưa chứng minh giá trị thực của bản ghi, việc gửi dữ liệu thành công hay mối liên hệ giữa hai hàm.

Điểm ở bảng dưới dùng các mục đã khóa theo từng mẫu. Nhận định đúng ngoài phạm vi được ghi riêng, không cộng vào số mục đúng theo đáp án. Một câu về đối số của lời gọi chỉ được chấm theo nội dung câu khẳng định. Nhận định sai và nhận định thiếu căn cứ đều vào mẫu số precision. Kết quả thuộc tập phát triển do nhóm đối chiếu nguồn. [Kế hoạch chốt trước](../eval/adjudications/table-access-protocol.json) · [Điểm, tọa độ và mã băm](../deliverables/real-demo-evidence/table-access-comparison.json)

| Mẫu và phiên bản | Mục đúng | Sai / thiếu căn cứ | Precision | Recall | F1 | Công cụ / giây |
|---|---:|---:|---:|---:|---:|---:|
| Gomorrah, trước | 12/40 | 0 / 3 | 80,00% | 30,00% | 43,64% | 17 / 512,8 |
| Gomorrah, kiểm đối số | 15/40 | 2 / 2 | 78,95% | 37,50% | 50,85% | 17 / 602,8 |
| Mercurial, trước | 5/21 | 0 / 1 | 83,33% | 23,81% | 37,04% | 17 / 460,5 |
| Mercurial, kiểm đối số | 5/21 | 1 / 1 | 71,43% | 23,81% | 35,71% | 17 / 571,4 |

Gomorrah bổ sung được hai mục đọc trường từ kho trình duyệt và một mảnh địa chỉ có vị trí sử dụng. Precision giảm. Trong 25 mục bỏ sót còn 8 mục thiếu dòng từ VM và 17 mục đã có đủ dòng trong cùng một yêu cầu sinh nhận định. Mercurial còn 16 mục bỏ sót. Trong đó có 6 mục thiếu dòng, 5 mục chưa tới bước sinh nhận định, 1 mục có dòng nằm rải ở nhiều lần hỏi, 4 mục đã đủ dòng trong một lần hỏi. Cả hai lượt mới đều cho `suspicious`, chưa khớp nhãn độc trên tập tham chiếu này.

## Lần kiểm riêng trên Mercurial

ILSpy có thể trả mã C# mà một số hàm bị lỗi cú pháp. Bộ đọc cũ bỏ qua toàn bộ tệp. Bản sửa chỉ xét các phương thức có thân và khối khai báo hợp lệ cho phép kiểm biến đọc cục bộ. Các phép kiểm kiểu cần ngữ cảnh toàn tệp vẫn giữ điều kiện cũ. [Kế hoạch trước khi chạy](../eval/adjudications/intact-method-protocol.json)

Lượt `20261128T110548_0cb9678e` qua web dùng cùng mẫu và Qwen. VM trả 8 vị trí truyền chỉ số, cả 8 vào báo cáo. Trên mỗi kích thước 390 px và 1360 px, trình duyệt mở đúng 24 trích dẫn và đi từ bảng điểm về đúng bản đồ. Tuy vậy câu C2 tự gán ba ý nghĩa cụ thể cho ba chỉ số. Đoạn dẫn không chứa lược đồ tương ứng. Báo cáo chỉ đúng **4/21 mục**, 1 sai, 3 ý thiếu căn cứ, bỏ sót 17. Precision **50,00%**, recall **19,05%**, F1 **27,59%**, verdict `suspicious`. Thời gian 677,7 giây, 17 lần gọi công cụ, 50 lần gọi model. Đây là lần thử riêng sau khi đã quan sát lỗi ở mẫu phát triển. [Biên bản hiển thị](../deliverables/real-demo-evidence/intact-method-check.json) · [Bảng chấm câu](../eval/adjudications/transfer-live-20261128T110548_0cb9678e.json) · [Số đo và nhật ký hỏi đáp](../deliverables/real-demo-evidence/web-20261128T110548_0cb9678e.json)

Hai lần thử hỏi về tên hoặc chỉ số cột đã bị định tuyến sang verdict và ngoài phạm vi. Luồng hiện tại tra cứu trực tiếp sự kiện đã lưu khi hồ sơ đã có kết quả đọc cột và câu hỏi nêu rõ loại đối số này. Lần kiểm sau đó mở đúng ba trích dẫn của ví dụ trả lời. Phần hỏi về một đường nối còn thiếu vẫn có thể gọi Qwen và tìm thêm trong VM. Câu trả lời tra cứu không thay đổi điểm của báo cáo gốc.

Việc tiếp theo là kiểm các tên trường Qwen tự gán trong phần viết tự do với nguồn lược đồ, rồi thử lại theo cùng quy tắc chấm trên cả mẫu độc và lành. Việc tìm thêm 8 vị trí ở đây giúp người đọc kiểm câu C2, trong khi độ phủ toàn báo cáo giảm một mục so với lượt trước.

## Đối chứng các chức năng của đồ án

Từ một bản clone, có thể tính lại bảng điểm và các thống kê từ biên bản công khai bằng lệnh dưới đây. Trên máy lab giữ nhật ký gốc, thêm `--replay` để kiểm lại từng trích dẫn, lần hỏi model và câu được giữ. Để có kết quả phân tích mới, dùng nút **Chạy điều tra**.

```powershell
.\.venv\Scripts\python.exe -m eval.table_access_study
```

- **Tìm cố định và điều tra theo giả thuyết.** Trên mười liên kết có đáp án của hai mẫu, luồng cố định tìm đúng 1, agent tìm đúng 3. Mỗi bên dùng tám lần tìm trong VM. Thời gian tìm cộng dồn tương ứng 4,587 và 14,540 giây. [Bảng theo mẫu](WEB_DIEU_TRA.md#kết-quả-đối-chứng-trên-hai-mẫu-phát-triển)
- **YARA.** Dùng tab YARA để xem luật trước và sau khi có phản hồi từ tập sạch. Năm mẫu độc được dùng trong phát triển. Cần một tập độc giữ riêng để đo TPR trên mẫu mới. [Tập dữ liệu và kết quả quét](YARA_REAL_CORPUS.md)
- **Huấn luyện.** Bộ xếp hạng chứng cứ có dữ liệu, cấu hình, checkpoint và lệnh train lại. Qwen dùng trọng số có sẵn. Người phân tích có thể gán nhãn trong web. Cần thêm nhãn có người đọc nguồn xác nhận để đo tác động của lần huấn luyện tiếp theo lên báo cáo cuối. [Hồ sơ train](../training/RANKER_EXPERIMENT.md)
- **ATT&CK.** Khi chấm T1555.003, đối chiếu nguồn dữ liệu trình duyệt và thao tác truy cập. Với T1560.002, kiểm thao tác lưu trữ bằng thư viện và dữ liệu đi vào thao tác đó. Một tên import chỉ là dấu hiệu để điều tra. [MITRE T1555.003](https://attack.mitre.org/techniques/T1555/003/) · [MITRE T1560.002](https://attack.mitre.org/techniques/T1560/002/)
