# Kiểm chứng một đường nối trên mẫu PythonStealer

Trong ba lượt trước, báo cáo bỏ sót mục A09 mặc dù công cụ từng đọc được cả phía gọi và thân hàm. Mục này hỏi liệu một trường cụ thể trong kết quả truy vấn có thực sự đi vào hàm xử lý hay không. Nhóm dùng cùng mẫu phát triển, cùng Qwen3 8B, cùng cấu hình và cùng 36 mục tham chiếu để kiểm tra thay đổi. [Bảng đối chứng ba lượt trước](DO_ON_DINH_BAN_DIEU_TRA.md)

## Kiểm ngay khi vấn đáp

1. Trên máy lab, chạy `.\scripts\Start-Web.ps1` trong PowerShell tại thư mục dự án, mở `http://127.0.0.1:4180`, chọn **public_python2024.bin** và bấm **Chạy điều tra**. Máy thật chạy web, bộ điều phối và Ollama. VM cô lập giữ tệp và chạy các công cụ phân tích. [Hướng dẫn cài trên máy nhóm](TEAM_SETUP.md)
2. Trong **Nhật ký**, tìm lần agent đặt câu hỏi về đường nối **Đọc kết quả truy vấn → Xử lý dữ liệu**. Model chọn một truy vấn từ phạm vi được phép. Bộ điều phối thấy quan hệ còn thiếu và yêu cầu VM kiểm tra luồng đối số khi tìm lại nguồn.
3. Trên **Bản đồ chứng cứ**, bấm vào đường nối đó, mở **Xem đoạn mã đã dẫn**. Đối chiếu cột thứ ba của truy vấn, đối số thứ nhất tại nơi gọi và nơi sử dụng tham số trong thân hàm. Đường nối mang trạng thái **Có bằng chứng** khi kết quả VM, SHA-256 của đầu ra và tất cả các dòng được trích khớp nhau.
4. Bấm **Mở C… trong báo cáo** để kiểm tra câu agent giữ. Trong **Hỏi đáp**, hỏi “Bản ghi nào được truyền vào hàm xử lý?”. Với quan hệ đã xác minh, câu trả lời dẫn lại nguồn và ghi nhật ký phiên hỏi. Với quan hệ còn thiếu, một câu hỏi khác có thể kích hoạt tìm thêm trong VM. [Luồng hỏi đáp và giới hạn công cụ](WEB_DIEU_TRA.md)
5. Mở **Đánh giá → Từ trường truy vấn đến hàm xử lý · hai lượt Python**. Trên máy lưu nhật ký, nút mở nhận định đưa tới đúng lượt. Thành viên mới chạy mẫu trên máy của mình để tạo hồ sơ cục bộ. Cuối buổi bấm **Tắt lab**.

## Phép kiểm trong VM

VM đối chiếu thứ tự cột trong truy vấn, chỉ số lấy từ hàng kết quả, vị trí đối số và cách thân hàm sử dụng tham số tương ứng. Kết quả gắn với SHA-256 của mẫu, đầu ra công cụ và các dòng làm chứng. Khi gặp phép chiếu không xác định, tham số bị gán lại hoặc cửa sổ quan sát thiếu dòng, hệ thống giữ quan hệ ở trạng thái chưa xác minh. Các kiểm thử phần mềm dùng ví dụ cơ sở dữ liệu đo đạc để kiểm tra cả trường hợp đúng lẫn trường hợp phải từ chối nối. [Bộ phân tích tĩnh](../vm_tools/row_use.py) · [Các phép thử đối chứng](../tests/test_row_use.py)

Trên mẫu phát triển, các vị trí nguồn là dòng 142 cho truy vấn, 143 cho hàng kết quả, 144 cho đối số, 69 cho tham số và 73 cho lời gọi xử lý. Bản đồ còn để mở quan hệ từ xử lý tới ghi tệp và từ ghi tệp tới nội dung bản nén. Quan sát mã tĩnh ở đây chưa đủ để khẳng định tệp chứa dữ liệu nào khi chạy, hay máy nhận đã nhận được gì.

## Hai lần bấm Chạy điều tra

| Kết quả sau tự duyệt | Cấu hình cũ, ba lượt | Lượt C31 | Lượt C34 sau khi siết phép kiểm |
|---|---:|---:|---:|
| Mục đúng trên 36 mục tham chiếu | 20, 20, 19 | 21 | 21 |
| Precision | 100% cả ba lượt | 95,45% | 100% |
| Recall | 55,56%, 55,56%, 52,78% | 58,33% | 58,33% |
| F1 | 71,43%, 71,43%, 69,09% | 72,41% | 73,68% |
| Đường nối có chứng cứ trên 7 đường | 3 cả ba lượt | 4 | 4 |
| Verdict agent / nhãn tham chiếu | suspicious / malicious | suspicious / malicious | suspicious / malicious |
| Số lần gọi công cụ / model | Xem ba nhật ký gốc | 17 / 43 | 17 / 45 |
| Thời gian phân tích | Xem ba nhật ký gốc | 456,49 giây | 575,75 giây |

Trình duyệt mở đủ bốn khoảng nguồn của cả đường nối và câu trong báo cáo ở 390 px và 1360 px. Cả hai lượt đều sử dụng bốn công cụ phân tích thành công và khớp luật YARA trên mẫu phát triển. Lượt C34 có thêm kiểm tra về kiểu dữ liệu của cột, kiểu hàng SQLite tùy biến và nhiều lệnh trên một dòng. Hai lượt dùng hai bản mã lõi, vì vậy phép đo độ ổn định ba lần trên phiên bản mới còn mở. [Nhật ký rút gọn C31](../deliverables/real-demo-evidence/web-20261128T084808_81ca89a3.json) · [Điểm C31](../deliverables/real-demo-evidence/transfer-live-20261128T084808_81ca89a3.json) · [Nhật ký rút gọn C34](../deliverables/real-demo-evidence/web-20261128T085636_4eaac445.json) · [Điểm C34](../deliverables/real-demo-evidence/transfer-live-20261128T085636_4eaac445.json)

Trong lượt C34, câu hỏi về đối số mở lại bốn khoảng đã có. Câu hỏi về tệp tại thời điểm nén gọi VM một lần, tìm được tám kết quả và mở đúng hai vị trí mới. Giữa hai lần kiểm giao diện, phiên web cũ còn dùng câu trả lời tổng quát cho quan hệ đã xác minh. Nhật ký giữ cả lần đó. Trình duyệt với mã web mới đã kiểm lại câu trả lời có cả tọa độ bên gọi và bên xử lý.

Mẫu tham chiếu thuộc tập phát triển do dự án đối chiếu. Trên cấu hình sau cùng, precision vượt ngưỡng 80% của slide. Recall còn dưới 70%, F1 còn dưới 75% và verdict chưa khớp. F1 trên 36 mục này gộp hành vi, IOC và ATT&CK. Điểm toàn đồ án cần kết quả trên nhiều mẫu, đối chứng độc lập và tái lập trên máy nhóm. [Chỉ tiêu gốc của giảng viên](YEU_CAU_GIANG_VIEN.md) · [Công việc còn lại](CONG_VIEC_CON_LAI.md)

## Đối chứng và huấn luyện

Phép đối chứng truy xuất cố định và thích nghi trước đó cho thấy trên Gomorrah, cùng bốn lượt công cụ, agent tìm được 2/7 mục và quy trình cố định tìm được 0/7. Trên Python, hai cách đều tìm được 1/3 mục và agent dùng thêm bốn lượt model. Đây là phép đo tìm liên kết. Bảng 36 mục chấm toàn báo cáo ở lượt web là một phép đo khác. [Dữ liệu của hai quy trình](../deliverables/real-demo-evidence/web-comparison.json)

Nhóm train bộ xếp hạng để ưu tiên vị trí đáng đọc. Trên phép thử trước/sau ở AgentTesla, số câu có đủ bằng chứng tăng từ 9/12 lên 10/12, nhưng cả hai phương án cùng phủ 2/7 mục tham chiếu. Web cho người đọc ghi nhãn có nguồn để train lại bộ xếp hạng. Qwen dùng trọng số có sẵn. [Mã train, checkpoint và kết quả trước/sau](../training/RANKER_EXPERIMENT.md)

## Kiểm lại số liệu

Trong môi trường Python của dự án, chạy `python -m eval.argument_review` để đối chiếu các bản ghi công khai. Trên máy giữ nhật ký gốc có thể thêm `--private` để đối chiếu câu và trích dẫn với báo cáo thực, quyết định của bộ duyệt và lần bấm trong trình duyệt. Các bản ghi công khai chứa tọa độ, mã băm và kết quả đo. Trích đoạn mã được mở trong web cục bộ.
