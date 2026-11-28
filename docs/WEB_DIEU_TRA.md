# Demo điều tra bằng trình duyệt

Trên máy Windows đã dựng lab của nhóm, mở PowerShell ở thư mục chứa `agent_react.py` và chạy:

```powershell
.\scripts\Start-Web.ps1
```

Mở **http://127.0.0.1:4180**. Script bật VM và Ollama, đồng bộ mã công cụ và đối chiếu hash hai phía trước khi mở web. Giao diện điều tra dùng **qwen3:8b**. Máy đã cài bản mặc định 7B cần bổ sung 8B theo hướng dẫn demo. Khi chỉ muốn xem hồ sơ cũ, chạy `.\scripts\Start-Web.ps1 -HistoryOnly`. Trên máy mới cần hoàn thành bước dựng lab trước. [Cài máy thành viên](TEAM_SETUP.md) · [Cài cấu hình 8B](DEMO_COVERAGE.md)

## Một lượt trình bày

1. Kiểm tra mục Ollama và VM ở góc phải. Bấm vào đó để đọc lại trạng thái từ hai dịch vụ. Chọn mẫu trong danh mục đã khóa SHA-256. Tên và kích thước hiển thị lấy từ manifest.
2. Bấm **Chạy điều tra** rồi mở **Nhật ký**. Trình duyệt gọi entrypoint của agent, dùng model thật và các công cụ đọc tĩnh trong VM. Mỗi lượt có mã mới. Tên công cụ, mã lượt và sự kiện trên màn hình đến từ tiến trình đang chạy. Trong lúc chờ, có thể mở một hồ sơ cũ ở cột Lịch sử. Tiêu đề hồ sơ cho biết đang xem lượt nào.
3. Mở **Bản đồ chứng cứ** sau khi hoàn tất. Chọn một nút để xem thao tác và tọa độ công cụ. Chọn đường nối bên dưới nút để xem quan hệ giữa hai thao tác. Màu xanh biểu thị có bằng chứng cho mệnh đề tĩnh đó. Màu vàng biểu thị còn thiếu bằng chứng. Màu xám biểu thị chưa tìm thấy trong phạm vi đã đọc. Với quan hệ còn thiếu, giao diện chỉ ra phần đã thấy ở hai đầu.
4. Đối chiếu một câu ở **Nhận định** với bản đồ. Nhận định là kết quả sau lọc của agent. Bản đồ kiểm tra các lời gọi và liên kết mà bộ phân tích hỗ trợ. Một câu có trích dẫn vẫn có thể sai ngữ nghĩa. Mở **Hỏi đáp**, hỏi về một quan hệ cụ thể. Khi đủ căn cứ, câu trả lời dẫn lại chứng cứ. Khi còn thiếu, Qwen chọn một truy vấn giới hạn, VM tìm trong đúng nguồn của lượt đó. Sau khi VM khởi động lại, một số mã chứng cứ cũ sẽ hết hiệu lực. Lượt hỏi vẫn ghi lỗi và phần chưa xác minh.
5. Mở **YARA** để xem kết quả quét tệp gốc sau verdict hoặc chạy lại quá trình tạo luật trên bộ phát triển. Mở từng lượt để xem các lần thử, số báo nhầm và nội dung bộ luật đã cố định. Chỉ số TPR dùng mẫu phát triển. Tập sạch giữ riêng dùng đánh giá FPR sau khi đã cố định luật.
6. Mở **Gán nhãn** để đánh giá những điểm tìm kiếm có đủ ngữ cảnh. Chỉ chọn nhãn khi đã đọc dòng nguồn. Kết thúc demo, đợi tác vụ hiện hành hoàn tất rồi nhấn **Ctrl+C** trong PowerShell chạy web. Launcher tắt model và VM của dự án.

### Máy nào làm gì?

| Thành phần | Trách nhiệm |
|---|---|
| Trình duyệt trên Windows | Chọn mẫu theo ID, mở bản đồ, xem trích dẫn, hỏi và lưu nhận xét. Server chỉ lắng nghe trên địa chỉ loopback. |
| Agent và Ollama trên Windows | Chọn hành động theo quan sát trước, nhận bằng chứng đã chiếu lọc, tạo nhận định và ghi nhật ký. Yêu cầu ghi từ web được ràng buộc với origin và khóa phiên. |
| Ubuntu VM cô lập | Giữ byte mẫu, xác minh SHA-256, dùng pefile/ILSpy hoặc PyInstaller/pycdc/pycdas và YARA. Mẫu được đọc tĩnh qua danh sách công cụ cho phép. |

### Một liên kết được kiểm tra thế nào?

Mỗi thao tác có mã bằng chứng, SHA-256 mẫu và SHA-256 đầu ra công cụ. Bộ điều phối theo dõi quan hệ còn thiếu, chọn từ khóa theo nền tảng hoặc tên hàm đã thấy, cho Qwen chọn phép tìm rồi cập nhật trạng thái sau quan sát. Bằng chứng của hai mẫu hoặc hai đầu ra dịch ngược khác nhau không được ghép với nhau.

Bộ kiểm tra nhận các trường hợp hẹp có thể truy nguyên, chẳng hạn truy vấn và lần lấy kết quả bằng cùng con trỏ, hoặc giá trị trả về của UploadFile đi vào bộ giải mã phản hồi. Với MIME, bộ kiểm tra theo dõi biến nhận kết quả tuần tự hóa tới đối số thông điệp. Việc gán lại biến hoặc thiếu dòng liên quan khiến quan hệ đó còn mở.

Với một số chương trình Python, VM kiểm tra thêm hàm tạo bản nén, giá trị trả về, đối số ở nơi gọi và tham số dùng để mở tệp làm phần đính kèm. Khi các ràng buộc đều khớp, đường nối hiển thị cả tọa độ trung gian. Đường dẫn, nội dung thực tế trên đĩa và việc máy đích nhận được thông điệp vẫn cần bằng chứng thời gian chạy riêng. Bản đồ hiển thị trích đoạn cục bộ đã che giá trị chuỗi.

Đối chiếu ATT&CK cần kiểm tra ý nghĩa dữ liệu. Một lời gọi SQL chưa đủ xác định truy cập mật khẩu trình duyệt. Một hàm nén cũng chưa đủ xác định lưu trữ dữ liệu đã thu thập. [T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) · [T1560.002 – Archive via Library](https://attack.mitre.org/techniques/T1560/002/)

## Huấn luyện từ nhận xét

Nhãn do người vận hành nhập được lưu cục bộ dưới `evidence/local/web-feedback/` với mã lượt, dòng, hash và phiên bản schema. Nhãn ở trang **Gán nhãn** có thêm 13 đặc trưng tính từ cửa sổ nguồn mà VM thực sự trả về. Một nguồn thiếu hàng lân cận sẽ không trở thành ví dụ huấn luyện. Nhãn ở thẻ thao tác phục vụ đối chiếu mệnh đề đó.

Sau khi có nhãn thật cho ít nhất một mẫu thuộc tập train, chạy:

```powershell
.\.venv\Scripts\python.exe -m training.train_web_ranker
```

Mỗi thí nghiệm tạo thư mục riêng trong `private/web-ranker` với corpus, loss, trọng số ứng viên và chỉ số trước/sau trên cùng phân chia theo mẫu. Chương trình kiểm lại nguồn của từng nhãn và giữ nguyên tập validation/test. Khi hai nhãn mâu thuẫn cần đối chiếu lại trước lúc train. Bước triển khai trọng số mới cần thí nghiệm đầu-cuối sau đó. Qwen vẫn dùng trọng số gốc. [Thí nghiệm xếp hạng đã chạy](../training/RANKER_EXPERIMENT.md)

## Tái lập phép so sánh

```powershell
.\.venv\Scripts\python.exe -m eval.compare_link_search
```

Hai phương án dùng cùng SHA-256 mẫu, cùng bản dịch ngược khởi đầu, cùng bộ trích chứng cứ và tối đa bốn lượt tìm trên mỗi mẫu. Phương án cố định dùng danh sách truy vấn công bố trong mã. Phương án điều tra dùng quan sát và model để chọn truy vấn. Kết quả tách số liên kết tham chiếu tìm đúng, số bỏ sót, số sai tại vị trí chấm, số lần gọi và thời gian. Liên kết nằm ngoài các vị trí đã chấm được thống kê riêng. Chi phí chuẩn bị dùng chung và thời gian viết báo cáo cuối nằm ngoài phép đo này.

### Kết quả đối chứng trên hai mẫu phát triển

Mười vị trí chấm gồm bảy quan hệ xử lý phản hồi trong mẫu .NET Gomorrah và ba quan hệ truy vấn/MIME trong mẫu Python. Điểm được tính từ cặp tọa độ của nguồn và đích. Hai phương án đều dùng bốn lần tìm trong VM cho mỗi mẫu.

| Mẫu | Tìm cố định | Agent điều tra | Thời gian cố định / agent |
|---|---:|---:|---:|
| Gomorrah (.NET), 7 vị trí | 0/7 | 2/7 | 3,746 s / 9,305 s |
| Python/PyInstaller, 3 vị trí | 1/3 | 1/3 | 0,841 s / 5,235 s |
| Tổng | 1 đúng, 9 bỏ sót | 3 đúng, 7 bỏ sót | 4,587 s / 14,540 s |

Ở các vị trí có đáp án, cả hai phương án đều có 0 lần nối sai nguồn. Phương án cố định còn 1 quan hệ nằm ngoài danh sách chấm, agent còn 2. Agent dùng tổng cộng 8 lần gọi Qwen để điều hướng, quy trình cố định dùng 0. Chi phí và thời gian trên chỉ tính giai đoạn tìm chứng cứ. Bộ phát triển nhỏ, trình tự chạy và cache cũng ảnh hưởng đến độ trễ. Các số này không thay F1 của báo cáo toàn mẫu.

Thử nghiệm đầu cho kết quả bất lợi: agent tìm đúng 0/10 và quy trình cố định tìm đúng 1/10. Nhật ký cho thấy truy vấn khác nền tảng và thao tác nằm trong cửa sổ tìm nhưng chưa được đưa vào danh sách kiểm kiểu. Nhóm bổ sung lọc truy vấn và kiểm các lời gọi trong phần mã VM thực sự đã trả, rồi so lại hai phương án. Việc sửa có sử dụng quan sát từ chính bộ phát triển này. [Lượt đầu](../deliverables/real-demo-evidence/web-comparison-initial.json) · [Lượt sau](../deliverables/real-demo-evidence/web-comparison.json)

## Tệp cục bộ sau khi chạy

- `runs/<run_id>/events.jsonl` lưu nhật ký agent theo chuỗi hash. `report.md` và `report.redacted.json` lưu kết quả, verdict và các giới hạn.
- `runs/<run_id>/questions/` lưu câu hỏi, chủ đề được chọn, lần tìm thêm, đáp án và trích dẫn.
- `runs/<run_id>/yara/` lưu biên bản quét trên tệp gốc. `runs/yara_real_*/` lưu thí nghiệm sinh luật độc lập.
- Hồ sơ riêng chỉ được phục vụ qua các trường đã chọn trên web cục bộ. Trên Git, nhóm công bố số liệu và hash đã kiểm tra. [Yêu cầu gốc](YEU_CAU_GIANG_VIEN.md) · [Việc còn lại](CONG_VIEC_CON_LAI.md)
