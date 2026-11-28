# Từ kết quả tìm trong VM tới nhận định có thể kiểm tra

Sau bốn lần tìm thêm trên cùng một mẫu, agent có viết được điều gì mới và đúng? Người trình bày có thể mở hồ sơ gốc và phụ lục để trả lời bằng chứng cứ. Mỗi phụ lục có riêng lịch sử truy vấn, các câu Qwen giữ hoặc loại và đoạn nguồn đã dùng cho từng câu.

## Chạy trực tiếp trên máy lab

1. Mở PowerShell ở thư mục dự án, chạy `.\scripts\Start-Web.ps1` và mở `http://127.0.0.1:4180`. Chọn một lượt điều tra .NET đã hoàn tất bằng Qwen3 8B, hoặc chạy **Chạy điều tra** để tạo lượt mới. Khi demo trước lớp, có thể dùng hồ sơ Gomorrah đã có trên máy lab.
2. Mở **Nhận định → Điều tra bổ sung trên mã .NET → Tìm thêm và lập phụ lục**. VM dịch ngược lại mẫu bằng ILSpy. Agent đối chiếu SHA-256 của mẫu, toàn bộ đầu ra dịch ngược và digest của model với hồ sơ được chọn. Vì VM tạo mã chứng cứ mới sau mỗi lần khởi động, sự đối chiếu này cho phép dùng lại hồ sơ sau khi tắt máy lab.
3. Agent thực hiện hai truy vấn từ danh sách có sẵn và tối đa hai truy vấn Qwen chọn theo kết quả vừa quan sát. Mỗi lượt tìm chỉ nhận tên mẫu đã xác minh, mã chứng cứ của VM và một chuỗi tìm kiếm. VM trả về các vùng có kết quả. Agent lấy tối đa bốn đoạn có dòng mới so với hồ sơ gốc. Nếu một truy vấn trả nhiều vị trí, bộ chọn ưu tiên cho các truy vấn khác một lượt trước khi chọn vị trí thứ hai.
4. Qwen đọc các đoạn đã chọn, đề xuất nhận định rồi duyệt lại từng câu. Mở câu và bấm **Xem đoạn mã đã dẫn** để xem mã đã che giá trị nhạy cảm, số dòng và hash đầu ra ILSpy. Khi mở lại hồ sơ, web đọc phụ lục hoàn tất gần nhất từ nhật ký. Các lần cũ nằm ở `runs/<lượt>/supplements/<mã phụ lục>/events.jsonl`. Đóng buổi demo bằng **Tắt lab**.

Ở máy mới, bảng **Đánh giá → chọn mẫu → Tìm lại dòng nguồn còn thiếu** có sẵn dữ liệu công bố. Nút điều tra trực tiếp cần VM, model và một lượt điều tra thật của máy đó. [Cài máy nhóm](TEAM_SETUP.md)

## Chấm từ câu đến điểm báo cáo

Hai nhánh đối chứng dùng nguyên 16 phản hồi tìm kiếm thật đã ghi từ VM. Qwen chạy suy luận mới trên máy thật cho từng nhánh. Hai lượt web kết hợp dịch ngược và tìm lại trực tiếp trong VM. Mỗi nhánh có cùng ngân sách bốn lượt tìm cho mỗi mẫu và tối đa bốn đoạn để viết bổ sung. Khi chấm, nhóm giữ nguyên 40 mục Gomorrah, 21 mục Mercurial và hai báo cáo gốc. Các nhãn là kết quả đối chiếu của dự án trên tập phát triển. [Phép đo tầng truy xuất](CHAM_BA_MAU_WEB.md#tìm-thêm-chứng-cứ-trong-vm-trên-hai-mẫu-net)

Một câu có thể vừa nhận điểm cho vị trí gọi hàm vừa bị tính lỗi vì suy ra tác dụng chưa được chứng minh. Chẳng hạn, dòng 1069 của Gomorrah đọc giá trị, còn 1070 chuyển dữ liệu cho hàm xử lý. Qwen xác định đúng trường được đọc nhưng gán thao tác đọc cho sai hàm. Trên Mercurial, 75 xác nhận có lời gọi hàm liên quan đến cookie. Chỉ dẫn dòng 75 để kết luận hàm thực sự đánh cắp cookie là thiếu căn cứ.

Khi tính điểm ghép, nhóm lấy hợp các mục đúng trong báo cáo gốc và các câu phụ lục được giữ. Một mục lặp chỉ tính một lần. Phần sai hoặc thiếu căn cứ cũng được khử trùng theo nội dung trên từng mẫu. Phát hiện đúng ngoài hồ sơ được ghi trong phần đối chiếu. Mẫu số recall vẫn là số mục đã chốt. Mỗi phụ lục được ghép riêng với cùng báo cáo gốc. Verdict trên hồ sơ chính vẫn là verdict của lượt điều tra ban đầu.

## Kết quả trên cùng 97 mục đã chốt

Ba mẫu gồm PythonStealer, Gomorrah và Mercurial. Mỗi hàng giữ nguyên báo cáo Python và chỉ ghép hai phụ lục .NET của phương án tương ứng. Các phương án là ba phép so riêng. Chưa chạy lại ba báo cáo chính với một phiên bản agent thay thế.

| Phương án | Mục đúng | Bỏ sót | Sai hoặc thiếu căn cứ | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Báo cáo gốc | 35 | 62 | 4 | 89,74% | 36,08% | 51,47% |
| Thêm phụ lục từ truy vấn cố định | 41 | 56 | 12 | 77,36% | 42,27% | 54,67% |
| Thêm phụ lục từ truy vấn do Qwen chọn | 37 | 60 | 10 | 78,72% | 38,14% | 51,39% |
| Thêm phụ lục kết hợp chạy trên web | 39 | 58 | 9 | 81,25% | 40,21% | 53,79% |

Ở chế độ kết hợp, bốn mục tăng đều thuộc Gomorrah. Hai mục là vị trí mở dữ liệu Opera và Chrome mà công cụ trước đó chưa lấy đủ dòng. Hai mục khác đã có dòng trong hồ sơ cũ nhưng lần này mới được báo cáo đúng. Trên Mercurial, phụ lục kết hợp có năm câu được Qwen giữ và thêm **0 mục** trong 21 mục đã chốt. Một số câu nói đúng về thao tác HTTP nằm ngoài hồ sơ. Một số chi tiết lại thiếu chứng cứ về nguồn ảnh, thư mục tạm và việc truyền dữ liệu. F1 riêng Mercurial giảm từ 35,71% xuống 32,26%. Điểm trên tập phát triển chưa đủ để đưa phụ lục vào verdict tự động.

**Hai lần bấm trên trình duyệt.** Gomorrah có 7 câu đề xuất, giữ 6, mất 169,646 giây từ lúc bắt đầu tìm đến khi lập xong phụ lục. Mercurial có 7 câu, giữ 5, mất 155,256 giây. Mỗi lần có 4 lượt tìm trong VM và 14 lượt gọi Qwen, gồm 2 lượt chọn truy vấn và 12 lượt cho phần báo cáo. Thời gian này bắt đầu sau bước dịch ngược và đối chiếu hash. Cả hai lần mở lại được trích dẫn và dòng nguồn, hash báo cáo gốc trước và sau giống nhau. [Biên bản tương tác web](../deliverables/real-demo-evidence/web-dotnet-supplement-actions.json)

## Lệnh cho máy thành viên

- Trên bản clone có môi trường Python của dự án, chạy `python -m eval.followup_report_audit` để tính lại các điểm và kiểm tra nhãn với tọa độ đã công bố.
- Trên máy lab có các nhật ký riêng, chạy `python -m eval.followup_report_audit --replay`. Lệnh đối chiếu hash, dựng lại các đoạn đã chọn, so từng yêu cầu Qwen với yêu cầu đã ghi và tính lại báo cáo từ phản hồi thật đã lưu. Hai lệnh kiểm tra chạy ngoại tuyến.
- Muốn chạy suy luận mới trên 16 phản hồi đã thu, khởi động Ollama của dự án bằng `.\scripts\Start-LocalModel.ps1 -PromptCacheMiB 0`, chạy `python -m eval.followup_report_trial --live`, sau đó dùng `.\scripts\Stop-LocalModel.ps1`. Lượt mới có thư mục riêng trong `private/followup-reports`. Trên máy chưa có nhật ký nguồn, dùng nút điều tra trực tiếp để tạo phụ lục của chính nhóm.

Các điểm theo từng mệnh đề và lý do chấm được công bố kèm kết quả suy luận. [Bảng tính lại được](../deliverables/real-demo-evidence/web-dotnet-followup-reports.json) · [Nhãn đối chiếu](../eval/adjudications/dotnet-followup-reports.json)
