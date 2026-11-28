# Demo điều tra bằng trình duyệt

Trên máy Windows đã dựng lab của nhóm, mở PowerShell ở thư mục chứa `agent_react.py` và chạy:

```powershell
.\scripts\Start-Web.ps1
```

Mở **http://127.0.0.1:4180**. Script bật VM và Ollama, đồng bộ mã công cụ và đối chiếu hash hai phía trước khi mở web. Giao diện điều tra dùng **qwen3:8b**. Máy đã cài bản mặc định 7B cần bổ sung 8B theo hướng dẫn demo. Khi chỉ muốn xem hồ sơ cũ, chạy `.\scripts\Start-Web.ps1 -HistoryOnly`. Trên máy mới cần hoàn thành bước dựng lab trước. [Cài máy thành viên](TEAM_SETUP.md) · [Cài cấu hình 8B](DEMO_COVERAGE.md)

## Một lượt trình bày

Để minh họa cách kiểm tra một câu bị loại, mở Mercurial C8 rồi Gomorrah C5 ở mục **Nhận định**. Cả hai có nhật ký bấm thật và câu đọc lại, còn nguồn chỉ xác nhận đầy đủ trường hợp đầu. [Các bước, số dòng và hai kết quả](DOC_LAI_NHAN_DINH.md)

Nhóm đã chạy lại từ nút **Chạy điều tra** với mẫu PythonStealer trên web và Qwen3 8B. Lượt `20261128T035912_e9d2b879` mất 495,58 giây, có 17 lượt công cụ, 38 lượt model và 232 sự kiện. Bốn backend phân tích thành công. Một lần dịch ngược lỗi, agent tiếp tục qua bytecode. Bản đồ kết thúc và bản đồ trên web cùng xác nhận ba liên kết tĩnh. Hỏi về dữ liệu từ truy vấn tới giải mã đã kích hoạt một lượt VM, được tám kết quả và còn thiếu chứng cứ. Hỏi về bản nén trong thông điệp dẫn lại 11 vị trí. YARA khớp trên mẫu phát triển. [Biên bản lượt trực tiếp](../deliverables/real-demo-evidence/web-20261128T035912_e9d2b879.json)

Cả 30 câu đề xuất của lượt này trùng lượt Python đầu tiên khi đối chiếu văn bản, loại, giá trị, tọa độ và trích dẫn, sau khi chuẩn hóa mã chứng cứ theo nguồn. Bộ duyệt đổi hai quyết định, giữ C7 và loại C6. Dùng lại nhãn đã chấm cho đúng các câu trùng, kết quả sau lọc là 20/36 mục, precision 95,24%, recall 55,56% và F1 70,18%. Đây là một lượt lặp Python. Bảng gộp ba mẫu vẫn dùng ba lượt đã chọn ban đầu. Trên máy lab có thể chạy `python -m eval.web_demo_repeat` để tính lại. [Phiếu đối chiếu lượt lặp](../deliverables/real-demo-evidence/web-live-repeat-quality.json)

1. Kiểm tra mục Ollama và VM ở góc phải. Bấm vào đó để đọc lại trạng thái từ hai dịch vụ. Chọn mẫu trong danh mục đã khóa SHA-256. Tên và kích thước hiển thị lấy từ manifest.
2. Bấm **Chạy điều tra** rồi mở **Nhật ký**. Trình duyệt gọi entrypoint của agent, dùng model thật và các công cụ đọc tĩnh trong VM. Mỗi lượt có mã mới. Tên công cụ, mã lượt và sự kiện trên màn hình đến từ tiến trình đang chạy. Trong lúc chờ, có thể mở một hồ sơ cũ ở cột Lịch sử. Tiêu đề hồ sơ cho biết đang xem lượt nào.
3. Mở **Bản đồ chứng cứ** sau khi hoàn tất. Chọn một nút để xem thao tác và tọa độ công cụ. Chọn đường nối bên dưới nút để xem quan hệ giữa hai thao tác. Màu xanh biểu thị có bằng chứng cho mệnh đề tĩnh đó. Màu vàng biểu thị còn thiếu bằng chứng. Màu xám biểu thị chưa tìm thấy trong phạm vi đã đọc. Với quan hệ còn thiếu, giao diện chỉ ra phần đã thấy ở hai đầu.
4. Đối chiếu một câu ở **Nhận định** với bản đồ. Nhận định là kết quả sau lọc của agent. Bản đồ kiểm tra các lời gọi và liên kết mà bộ phân tích hỗ trợ. Một câu có trích dẫn vẫn có thể sai ngữ nghĩa. Mở **Hỏi đáp**, hỏi về một quan hệ cụ thể. Khi đủ căn cứ, câu trả lời dẫn lại chứng cứ. Khi còn thiếu, Qwen chọn một truy vấn giới hạn, VM tìm trong đúng nguồn của lượt đó. Sau khi VM khởi động lại, một số mã chứng cứ cũ sẽ hết hiệu lực. Lượt hỏi vẫn ghi lỗi và phần chưa xác minh.
5. Mở **YARA** để xem kết quả quét tệp gốc sau verdict hoặc chạy lại quá trình tạo luật trên bộ phát triển. Mở từng lượt để xem các lần thử, số báo nhầm và nội dung bộ luật đã cố định. Chỉ số TPR dùng mẫu phát triển. Tập sạch giữ riêng dùng đánh giá FPR sau khi đã cố định luật.
6. Mở **Gán nhãn** để đánh giá những điểm tìm kiếm có đủ ngữ cảnh. Chỉ chọn nhãn khi đã đọc dòng nguồn. Kết thúc demo, đợi tác vụ hiện hành hoàn tất rồi bấm **Tắt lab** ở đầu trang. Chờ PowerShell xác nhận VM và model đã dừng. Nếu đã ngắt cửa sổ bằng Ctrl+C, mở PowerShell ở thư mục dự án và chạy `.\scripts\Stop-Lab.ps1` để dừng và kiểm lại cả hai.

### Máy nào làm gì?

| Thành phần | Trách nhiệm |
|---|---|
| Trình duyệt trên Windows | Chọn mẫu theo ID, mở bản đồ, xem trích dẫn, hỏi và lưu nhận xét. Server chỉ lắng nghe trên địa chỉ loopback. |
| Agent và Ollama trên Windows | Chọn hành động theo quan sát trước, nhận bằng chứng đã chiếu lọc, tạo nhận định và ghi nhật ký. Yêu cầu ghi từ web được ràng buộc với origin và khóa phiên. |
| Ubuntu VM cô lập | Giữ byte mẫu, xác minh SHA-256, dùng pefile/ILSpy hoặc PyInstaller/pycdc/pycdas và YARA. Mẫu được đọc tĩnh qua danh sách công cụ cho phép. |

### Một liên kết được kiểm tra thế nào?

Ở hồ sơ Python `20261128T021511_bec5b2e5`, chọn đường nối **Tuần tự hóa thông điệp → Gọi API gửi** rồi mở **Các lần agent kiểm tra liên kết**. Bước 11 tìm thấy một vị trí với `sendmail` nhưng liên kết còn thiếu chứng cứ. Sau bước 12 với `as_string`, trạng thái trong nhật ký chuyển sang **Có bằng chứng**. Bấm **Xem đoạn mã đã dẫn** để đọc các dòng mang dấu mũi tên và các dòng lân cận đã quan sát. Dấu chấm lửng giữa các dòng thể hiện khoảng bị lược. Hash dưới đoạn mã định danh đầu ra công cụ. Mỗi mẫu và mỗi lượt có thể có lịch sử truy vấn khác.

Mỗi thao tác có mã bằng chứng, SHA-256 mẫu và SHA-256 đầu ra công cụ. Bộ điều phối theo dõi quan hệ còn thiếu, chọn từ khóa theo nền tảng hoặc tên hàm đã thấy, cho Qwen chọn phép tìm rồi cập nhật trạng thái sau quan sát. Bằng chứng của hai mẫu hoặc hai đầu ra dịch ngược khác nhau không được ghép với nhau.

Bộ kiểm tra nhận các trường hợp hẹp có thể truy nguyên, chẳng hạn truy vấn và lần lấy kết quả bằng cùng con trỏ, hoặc giá trị trả về của UploadFile đi vào bộ giải mã phản hồi. Với MIME, bộ kiểm tra theo dõi biến nhận kết quả tuần tự hóa tới đối số thông điệp. Việc gán lại biến hoặc thiếu dòng liên quan khiến quan hệ đó còn mở.

Với một số chương trình Python, VM kiểm tra thêm hàm tạo bản nén, giá trị trả về, đối số ở nơi gọi và tham số dùng để mở tệp làm phần đính kèm. Khi các ràng buộc đều khớp, đường nối hiển thị cả tọa độ trung gian. Đường dẫn, nội dung thực tế trên đĩa và việc máy đích nhận được thông điệp vẫn cần bằng chứng thời gian chạy riêng. Bản đồ hiển thị trích đoạn cục bộ đã che giá trị chuỗi.

Đối chiếu ATT&CK cần kiểm tra ý nghĩa dữ liệu. Một lời gọi SQL chưa đủ xác định truy cập mật khẩu trình duyệt. Một hàm nén cũng chưa đủ xác định lưu trữ dữ liệu đã thu thập. [T1555.003 – Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) · [T1560.002 – Archive via Library](https://attack.mitre.org/techniques/T1560/002/)

## Huấn luyện từ nhận xét

Trên web, vào **Gán nhãn → Xem cách train và kết quả trước/sau**. Trang đọc biên bản train thật, đối chiếu hash corpus, mã train và checkpoint dùng cho VM. Bộ xếp hạng được cập nhật 300 lần. Tập test có năm vị trí thuộc một nhóm truy vấn. Một kết quả đứng đầu đúng trên tập này chưa đủ để suy ra recall của cả báo cáo. [Mã train, loss và cách chia tập](../training/RANKER_EXPERIMENT.md)

Nhãn do người vận hành nhập được lưu cục bộ dưới `evidence/local/web-feedback/` với mã lượt, dòng, hash và phiên bản schema. Nhãn ở trang **Gán nhãn** có thêm 13 đặc trưng tính từ cửa sổ nguồn mà VM thực sự trả về. Một nguồn thiếu hàng lân cận sẽ không trở thành ví dụ huấn luyện. Nhãn ở thẻ thao tác phục vụ đối chiếu mệnh đề đó.

Sau khi có nhãn thật cho ít nhất một mẫu thuộc tập train, chạy:

```powershell
.\.venv\Scripts\python.exe -m training.train_web_ranker
```

Mỗi thí nghiệm tạo thư mục riêng trong `private/web-ranker` với corpus, loss, trọng số ứng viên và chỉ số trước/sau trên cùng phân chia theo mẫu. Chương trình kiểm lại nguồn của từng nhãn và giữ nguyên tập validation/test. Khi hai nhãn mâu thuẫn cần đối chiếu lại trước lúc train. Bước triển khai trọng số mới cần thí nghiệm đầu-cuối sau đó. Qwen vẫn dùng trọng số gốc. [Thí nghiệm xếp hạng đã chạy](../training/RANKER_EXPERIMENT.md)

## Tái lập phép so sánh

Mở **Đánh giá** để xem bảng chấm bốn mẫu v11 trước và sau tự duyệt, số lượt verdict đúng và kết quả tìm liên kết của hai phương án. Dòng tiêu đề ghi rõ phiên bản và tập được chấm. Mọi số liệu lấy từ biên bản thực nghiệm trong Git. Trên máy mới mục này đọc được ngay ở chế độ xem lịch sử.

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

## Hai câu hỏi để trình diễn trên hồ sơ Python

Trong **Nhật ký**, mục **Token, bộ nhớ và chi phí của lượt này** lấy số đo từ báo cáo cuối. RAM đỉnh ở đây thuộc tiến trình điều phối. Số VRAM là giá trị Ollama ghi ở cuối lượt. Mục thiếu số đo hiện “chưa đo”.

Trên máy demo, chọn lượt `20261128T021511_bec5b2e5`. Trên máy vừa cài, chọn mẫu Python/PyInstaller và chạy điều tra để tạo hồ sơ riêng. Lần đo dưới đây dùng Qwen3 8B, mất 376,77 giây, gọi model 38 lần và công cụ 17 lần. Một lần dịch ngược trả lỗi. Agent đã chuyển sang đọc bytecode để tiếp tục. Nhật ký có 232 sự kiện và bốn công cụ phân tích thành công. [Biên bản lượt Python](../deliverables/real-demo-evidence/web-20261128T021511_bec5b2e5.json)

| Thao tác trong web | Kết quả đã quan sát |
|---|---|
| Bấm đường nối từ **Tạo bản nén** đến **Tuần tự hóa thông điệp** | Mở 11 vị trí có cùng nguồn dịch ngược. Bản đồ trong nhật ký kết thúc và bản đồ hiển thị khớp nhau. |
| Hỏi “Có chứng cứ cho thấy tệp nén được đưa vào thông điệp email không?” | Qwen chọn đúng quan hệ. Hệ thống dẫn lại 11 vị trí trong hồ sơ. Số lượt tìm VM bổ sung bằng 0. |
| Hỏi “Bản ghi fetch có được xử lý giải mã không?” | Agent gọi tìm kiếm trong VM, nhận 8 kết quả. Chưa chứng minh được các bản ghi đó đi vào phép giải mã. Hệ thống giữ trạng thái cần kiểm tra thêm. |
| Mở **Nhật ký** và xem bước 12 | Phép tìm cho quan hệ giữa thông điệp và lời gọi gửi trả về một kết quả. Bộ kiểm chứng chuyển quan hệ sang trạng thái có bằng chứng sau khi đối chiếu nơi tạo và nơi dùng. |

Bản đồ cuối có 3/7 quan hệ được hỗ trợ, 4/7 cần kiểm tra thêm. Verdict của agent là `suspicious`. Đây là kết quả đọc tĩnh. Lượt .NET Gomorrah trước đó cũng ghi nhận một câu hỏi về bản nén và email. VM tìm thêm, thu được 0 vị trí và câu trả lời giữ nguyên mức chưa đủ căn cứ. [Biên bản .NET](../deliverables/real-demo-evidence/web-20261128T020459_8c1f0720.json)

Hồ sơ có bản đồ đã lưu sẽ hiển thị bản đồ tại thời điểm kết thúc lượt chạy. Với các lượt cũ hơn tính năng này, giao diện ghi rõ khi phải dựng lại sơ đồ từ nhật ký. Khi xem lịch sử, chỉ các nút cần chạy lab bị khóa. Nhóm vẫn có thể đọc nguồn và ghi nhận xét trên máy.

Đã thử tắt hẳn lab rồi khởi động lại bằng `Start-Web.ps1`. Hai dịch vụ đều sẵn sàng. Khi hỏi lại quan hệ đọc bản ghi và giải mã trên một hồ sơ của phiên VM trước, VM trả lỗi truy xuất nguồn. Web hiển thị hai vị trí liên quan đã lưu, ghi lỗi vào nhật ký câu hỏi và giữ kết luận chưa đủ căn cứ. Để demo tìm thêm bằng công cụ, hãy tạo lượt phân tích trong cùng phiên VM rồi hỏi trên lượt đó. [Biên bản sau khi mở lại lab](../deliverables/real-demo-evidence/web-20261128T023637_4ad0f5f6.json)

## Độ ổn định của ba lượt Python

Trong **Đánh giá**, bộ chọn **Mẫu dùng để đối chiếu** cho phép chuyển giữa PythonStealer, Gomorrah và Mercurial. Mỗi mẫu có bảng trước/sau tự duyệt, bảng từng câu và danh sách mục bỏ sót. Bảng tổng hợp ngay dưới tính mỗi mẫu đúng một lần. Có thể đối chiếu ba báo cáo công khai trên bản clone chỉ có Python của dự án, với lệnh `.\scripts\Start-Web.ps1 -HistoryOnly`. Chế độ chạy một mẫu mới cần lab đầy đủ. [Điểm của ba mẫu và điều kiện đo](CHAM_BA_MAU_WEB.md)

Để trình bày phần chấm chất lượng, mở **Đánh giá → Đối chiếu từng câu** ở lượt kết thúc bằng `4ad0f5f6`. So C12 với C16 để thấy hai loại lỗi của bộ tự duyệt. Mở **Mục còn thiếu** ngay bên dưới để xem từng mục bị mất ở khâu nào. Phần này đọc được cả khi mở web bằng `-HistoryOnly`. [Kết quả và cách tái lập](CHAM_BAO_CAO_WEB.md)

Ba lượt liên tiếp dùng cùng SHA-256 của mẫu, model, mã phân tích và cấu hình. Các lượt lần lượt giữ 29, 30 và 36 nhận định, mất 376,77, 399,07 và 495,93 giây. Cả ba gọi công cụ 17 lần và cùng đưa verdict `suspicious`. Số lượt gọi model lần lượt là 38, 38 và 49.

Theo phép chấm của dự án, 27/38 nhận định xuất hiện trong cả ba lượt, đạt **71,05%** so với ngưỡng **80%**. Đối với hành vi, cách diễn đạt khác nhau được tính riêng. Trên bản đồ, cùng ba quan hệ có bằng chứng ở cả ba lượt, bốn quan hệ còn lại đều cần kiểm tra thêm. Cần lặp lại phép đo trên mẫu giữ riêng. [Biên bản ba lượt](../deliverables/real-demo-evidence/web-stability-python.json)

Trên máy có đủ ba nhật ký, tái lập phép tính bằng lệnh sau. Trên máy khác, thay ba mã bằng ba lượt đã hoàn tất trên cùng một mẫu và phiên bản.

```powershell
.\.venv\Scripts\python.exe -m eval.web_stability 20261128T021511_bec5b2e5 20261128T022955_4014e541 20261128T023637_4ad0f5f6
```

## Kết quả YARA từ web

Để trình bày một báo nhầm thật, mở **YARA → Báo nhầm đã ghi trên tệp sạch**. Bộ luật đầu đánh dấu nhầm yt-dlp trong 1/38 tệp sạch. Nhóm đưa đúng tệp đó vào tập phát triển, sửa quy trình chọn dấu hiệu và sinh lại luật. Giao diện đối chiếu SHA-256 để xác nhận cùng tệp ở hai phép thử. Sau lần sửa, yt-dlp hết khớp và 38 tệp sạch giữ riêng đều qua. Đây là lịch sử hai phiên bản. Nút tạo luật phía trên chạy một thí nghiệm mới trong VM. [Bộ dữ liệu, biên bản và lịch sử sửa luật](YARA_REAL_CORPUS.md)

Nút **Tạo và kiểm thử luật trong VM** đã chạy trên tệp gốc. Một lượt tạo 5 luật trong 57,48 giây và gọi model 5 lần. Bộ luật phát hiện 5/5 mẫu phát triển. Một tệp sạch dùng trong phát triển và 38 tệp sạch giữ riêng đều không báo nhầm. Lần quét lại bộ luật đã cố định cho kết quả trùng khớp.. Tập giữ riêng hiện có 0 mẫu độc nên TPR trên mẫu độc chưa từng thấy vẫn chưa đo được. [Biên bản và số mẫu từng phần](../deliverables/real-demo-evidence/yara-runs/yara_real_8fd631667863/receipt.json)

Luật và từng lần thử xuất hiện trong thẻ YARA sau khi bấm mở mã lượt. Nhóm có thể so số lần biên dịch, lượt bị loại, khớp và báo nhầm theo từng mẫu. Trong lần kiểm lại bằng trình duyệt, cả năm luật đều đạt yêu cầu ngay từ lần thử đầu. [Lượt kiểm lại trên web](../deliverables/real-demo-evidence/yara-runs/yara_real_a2f8ca844220/receipt.json)

## Tệp cục bộ sau khi chạy

Đã kiểm tra nút **Tắt lab** sau khi dùng đúng lệnh mở web trên máy Windows. Launcher thoát bình thường, cổng web và Ollama đóng, VMware xác nhận VM đã tắt. [Biên bản dừng máy](../deliverables/real-demo-evidence/runtime-stopped-after-web.json)

- `runs/<run_id>/events.jsonl` lưu nhật ký agent theo chuỗi hash. `report.md` và `report.redacted.json` lưu kết quả, verdict và các giới hạn.
- `runs/<run_id>/questions/` lưu câu hỏi, chủ đề được chọn, lần tìm thêm, đáp án và trích dẫn.
- `runs/<run_id>/yara/` lưu biên bản quét trên tệp gốc. `runs/yara_real_*/` lưu thí nghiệm sinh luật độc lập.
- Hồ sơ riêng chỉ được phục vụ qua các trường đã chọn trên web cục bộ. Trên Git, nhóm công bố số liệu và hash đã kiểm tra. [Yêu cầu gốc](YEU_CAU_GIANG_VIEN.md) · [Việc còn lại](CONG_VIEC_CON_LAI.md)
