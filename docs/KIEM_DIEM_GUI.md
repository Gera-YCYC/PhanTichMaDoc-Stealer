# Từ lời gọi gửi trong mã đến nhận định có thể kiểm tra

## Chạy trên máy nhóm

1. Trên máy Windows đã chuẩn bị lab, mở PowerShell tại thư mục chứa `agent_react.py` và chạy `.\scripts\Start-Web.ps1`. Đợi dòng địa chỉ của StealerLab. Máy mới cần cài VM, model và bộ công cụ theo [hướng dẫn nhóm](TEAM_SETUP.md).
2. Mở `http://127.0.0.1:4180`, bấm trạng thái kết nối ở đầu trang và kiểm tra cả **Ollama** lẫn **VM**. Chọn `public_python2024.bin`, bấm **Chạy điều tra**. Tab **Nhật ký** hiển thị hành động và quan sát khi agent đang chạy.
3. Mở **Nhận định → Vì sao báo cáo đưa ra verdict này? → Kiểm tra lại điểm gửi**. Bấm mã câu, mở từng trích dẫn rồi đối chiếu dòng dùng để ràng buộc đối tượng với dòng gọi gửi. Mã lượt và SHA-256 cho phép một thành viên khác mở lại cùng chứng cứ.
4. Mở **Bản đồ chứng cứ**, chọn đường nối tới thao tác gửi và đọc trạng thái. Với đường nối còn thiếu, chọn **Hỏi tiếp về đường nối này**. Nhật ký câu hỏi lưu công cụ mà agent thực sự gọi thêm.
5. Có thể chạy cùng luồng trên đối chứng `clean_ms_addinprocess.bin`. Lab cần có đúng tệp Microsoft .NET AddInProcess 36.424 byte đã nhập theo [quy trình chuẩn bị bộ sạch](CLEAN_CORPUS.md). Sau buổi demo, bấm **Tắt lab** và chờ PowerShell xác nhận VMware cùng Ollama đã dừng.

## Điều kiện bổ sung một câu

Qwen đánh giá câu mô tả thao tác dựa trên những dòng công cụ đã trả. Sau bước tổng hợp verdict, agent tra lại các thao tác SMTP và tải tệp mà Qwen đã duyệt. Để bổ sung vai trò gửi, mã mẫu, kết quả dịch ngược, mã thao tác, mã câu, nội dung câu và **toàn bộ khoảng trích** phải khớp. Agent lưu các dòng xác định đối tượng và đối số cùng dòng gọi API. Câu chỉ mô tả giải mã phản hồi ở gần lời gọi tải lên sẽ trượt phép đối chiếu này.

Danh sách dẫn chứng verdict có tối đa 10 vị trí. Khi có câu gửi đủ điều kiện, bản chạy Python dành trước tối đa 5 vị trí, tùy số thao tác tìm được. Nhật ký lưu số vị trí dành trước, các câu Qwen đã dẫn và các câu được bổ sung. Nếu hết chỗ, giao diện vẫn hiển thị điểm gửi kèm trạng thái hết chỗ. Một lời gọi gửi xác nhận khả năng của mã tĩnh. Để chứng minh gửi thông tin nhạy cảm, vẫn cần chứng cứ cho nguồn dữ liệu và cách giá trị đó đi vào đối số gửi. Bước phục hồi giữ nguyên verdict đã có sau khi kiểm vai trò. [Mã đối chiếu](../stealer_agent/send_recovery.py) · [Luồng tạo báo cáo](../stealer_agent/evidence_cards.py)

## Phép thử trên các báo cáo đã chấm

Trong 19 cặp câu–vai trò đã khóa trước, **9 cặp** hỏi về thao tác gửi. So nguyên văn và trích dẫn tìm đúng 2/3 cặp dương và loại đúng 6/6 cặp âm. Hai câu tìm lại được là C22 trên Python và C25 trên Gomorrah. C1 trên Gomorrah cũng mô tả thao tác gửi đúng, nhưng Qwen tự viết câu này. Câu đã duyệt theo mẫu ở cùng dòng nguồn có một mã câu khác. Phép đối chiếu giữ nguyên sự khác biệt đó, nên tính C1 là bỏ sót. Đây là phép đo ở cấp câu trên dữ liệu phát triển. [Kết quả từng cặp](../deliverables/real-demo-evidence/send-site-retrieval.json)

```powershell
.\.venv\Scripts\python.exe -m eval.send_site_study
```

Thêm `--replay` trên máy giữ nhật ký gốc để tính lại từ các quan sát của VM. Tab **Đánh giá → Tìm đúng câu mô tả thao tác gửi** cho xem bảng đếm từ cùng biên bản.

## Đối chứng .NET có chữ ký

Lượt `20261128T124233_ca348a88` dùng Qwen3 8B, nhận diện tệp và ILSpy thật trong VM. Agent gọi công cụ **17 lần**, gọi model **27 lần**, hết **325,43 giây**, giữ **4 câu**, và trả `inconclusive`. Số điểm gửi được phục hồi là 0. Theo cách chấm lành/độc, lượt này đạt **0/1 verdict đúng**. Việc chữ ký hợp lệ là thông tin để chọn đối chứng. Bước kết luận không dùng nhãn đó làm đáp án. Tên tệp có chữ `clean` xuất hiện trong đầu vào điều tra, nên đây là ca phát triển công khai nhãn. Lượt này có trước thay đổi về việc dành chỗ cho trích dẫn ở lần tổng hợp đầu tiên. [Nhật ký tóm tắt của lượt đối chứng](../deliverables/real-demo-evidence/web-20261128T124233_ca348a88.json)

## Lượt PythonStealer qua nút Chạy điều tra

Lượt `20261128T124815_dca6f7b8` mất **471,59 giây**, gọi model 52 lần và gọi công cụ 17 lần. Có một lỗi ở bước dịch ngược Python. VM tiếp tục đọc tĩnh phần mã có thể khôi phục. Tổng hợp lần đầu dẫn chín câu. Bước phục hồi bổ sung C21 bằng ba trích dẫn ở dòng **14, 106 và 109**. Các trích dẫn đã mở được từ web ở cả chiều rộng 390 và 1360 px. [Quan sát, ngân sách, quyết định phục hồi và kết quả mở dòng](../deliverables/real-demo-evidence/web-20261128T124815_dca6f7b8.json)

Trên bộ 36 ý tham chiếu phát triển, báo cáo giữ 32 câu, tìm đúng **21/36 ý**, bỏ sót 15 ý. Precision 100%, recall 58,33%, F1 73,68%. Số ý đúng và F1 bằng lượt Python dùng để đối chiếu. Verdict vẫn là `suspicious` trên tệp đã biết là độc. C2 mô tả việc đính kèm và gửi tệp ZIP. Qwen dùng dòng 278 tạo đường dẫn ZIP làm nguồn nhạy cảm cho C2, trong khi bản đồ còn thiếu liên kết xử lý → ghi và ghi → nén. Vì vậy không thể tính C2 là bằng chứng đã nối nguồn dữ liệu nhạy cảm tới SMTP. Sai ở vai trò của câu được ghi riêng với điểm nội dung câu. [Bảng chấm theo ý](../deliverables/real-demo-evidence/transfer-live-20261128T124815_dca6f7b8.json) · [Hai câu cần chấm thêm bằng nguồn](../eval/adjudications/transfer-live-20261128T124815_dca6f7b8.json)

## Kiểm nguồn của dữ liệu trước khi giữ đường nối

Ở bản 17, khi Qwen đã chọn đủ ba vị trí cho một liên kết, agent còn kiểm vị trí mà Qwen coi là nguồn. Tại đó phải có một thao tác đọc đã được bộ phân tích nhận dạng, hoặc một câu thu thập đã qua kiểm tra phải dẫn cùng vị trí nguồn và có thao tác đọc được ràng buộc trong cùng đầu ra. Agent so mã mẫu, hash đầu ra, mã thao tác, dòng gọi và loại API. Phạm vi hiện tại gồm đọc tệp, sao chép tệp và đọc kết quả truy vấn. Các API chưa hỗ trợ có thể làm agent bỏ sót. Một điểm đọc khớp mới chỉ chứng minh được thao tác ở đầu nguồn; thành phần dữ liệu và đường đi tới đối số gửi vẫn cần đối chiếu.

Trên **4 cặp âm** về liên kết đã gán nhãn từ trước, Qwen duyệt nhầm 1 cặp. Sau khi đối chiếu lại cùng các dòng từ VM, còn 0/4 cặp được duyệt. C2 của lượt Python ở trên là ca chẩn đoán phát sinh sau, cũng bị loại khi kiểm dòng 278. Cả hai phép thử đều thiếu cặp dương đã gán nhãn độc lập, nên recall của bước kiểm liên kết chưa xác định. Để tính lại, chạy `.\.venv\Scripts\python.exe -m eval.link_source_study`; máy có nhật ký riêng có thể thêm `--replay`. [Các dòng được chọn và kết quả đối chiếu](../deliverables/real-demo-evidence/link-source-check.json)

Lượt đầu bật bản 17 dừng sau 38,61 giây khi RAM khả dụng xuống khoảng 198 MiB, thấp hơn ngưỡng 256 MiB. Agent đã giải phóng model và lưu trạng thái `incomplete`. Biên bản này được giữ trong lịch sử thử nghiệm. [Lượt dừng trước khi tổng hợp](../deliverables/real-demo-evidence/web-20261128T130106_348c46bd.json)

Lượt kế tiếp chạy hết với cùng giới hạn bộ nhớ. Trên PythonStealer, Qwen lại chọn dòng 278 cho nguồn nhạy cảm của C2. Bản 17 giữ vai trò gửi của C2, loại vai trò nối dữ liệu của C2 và phục hồi câu gửi C21. Có thể mở các dòng 278, 96, 109 từ hàng quyết định C2 và ba trích dẫn của C21 ở chiều rộng 390/1360 px. [Biên bản của lượt mới](../deliverables/real-demo-evidence/web-20261128T130249_0fdc121a.json)

| PythonStealer | Bản 16 | Bản 17 |
|---|---:|---:|
| Thời gian | 471,59 s | 453,45 s |
| Lần gọi model / công cụ / lỗi công cụ | 52 / 17 / 1 | 48 / 17 / 1 |
| Câu được giữ | 32 | 34 |
| Ý đúng / sai / thiếu căn cứ / bỏ sót | 21 / 0 / 0 / 15 | 21 / 1 / 0 / 15 |
| Precision / recall / F1 | 100% / 58,33% / 73,68% | 95,45% / 58,33% / 72,41% |
| Verdict / nhãn mẫu | suspicious / malicious | suspicious / malicious |

Các lượt dùng cùng SHA-256 mẫu, digest model và cấu hình suy luận. Nội dung báo cáo được sinh lại. Ở bản 17, C7 mô tả sai kiểu dữ liệu trả về. Bước kiểm nguồn sửa được lỗi vai trò của C2, trong khi recall toàn báo cáo giữ nguyên và F1 giảm. Bảng trên dùng nhãn theo từng ý đã khóa trước, tái sử dụng khi câu và trích dẫn trùng khớp. Nhóm còn thiếu phép thử trên mẫu giữ riêng và một bộ liên kết dương được đối chiếu độc lập. [Bảng chấm bản 17](../deliverables/real-demo-evidence/transfer-live-20261128T130249_0fdc121a.json)

Từ repo, chạy `python -m eval.link_source_study --compare-runs` để tính lại bảng so sánh. Trên máy có nhật ký gốc, dùng `python -m eval.link_source_study --verify-live 20261128T130249_0fdc121a` để kiểm lại từng yêu cầu, phản hồi, quyết định vai trò và việc bổ sung điểm gửi.
