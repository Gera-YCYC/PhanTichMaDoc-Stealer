# Đọc thao tác Python và trả lại IOC, ATT&CK

## Phạm vi thay đổi

Nhánh báo cáo theo đoạn trước đây chỉ sinh hành vi và quan sát. Điều đó làm thiếu IOC và ATT&CK dù mã đã được truy hồi. Bản `evidence-cards/9` thêm danh sách `supplemental_claims`: mỗi đoạn tối đa hai câu hành vi/quan sát và một IOC hoặc ATT&CK. Tất cả câu vẫn đi qua kiểm schema, citation và reviewer; câu bị loại vẫn nằm trong báo cáo thô và mẫu số đánh giá. Đây không phải bằng chứng rằng reviewer chấm đúng.

IOC phải là literal nhìn thấy, có vai trò tĩnh được mô tả chính xác. Hostname SMTP có thể là ứng viên cấu hình; không tự trở thành C2 đã quan sát. Placeholder che bí mật không phải IOC. Không đưa mật khẩu, token hoặc địa chỉ đăng nhập riêng tư vào bản công khai. ATT&CK phải có thao tác phù hợp: truy cập kho mật khẩu trình duyệt có thể hỗ trợ T1555.003; một lời gọi DPAPI riêng lẻ không chứng minh Windows Credential Manager. Nén dữ liệu bằng thư viện phải phân biệt với gọi tiện ích nén.

## Dữ kiện thao tác phiên bản 4

Parser trong VM đọc AST tĩnh, không import hoặc thực thi mã mẫu. Ngoài SQLite SELECT, AES-GCM, nén và gửi SMTP, bản `static-operation-facts/4` nhận diện các dạng có binding kiểm được:

- Sao chép file bằng `shutil.copy/copy2`, giữ riêng biểu thức nguồn và đích.
- Đọc/ghi file qua `open` không bị shadow, chế độ mở phù hợp; giữ riêng dữ liệu và đường dẫn. Tùy chọn mở không được hỗ trợ khiến parser bỏ nhận định.
- Base64 và `CryptUnprotectData`, không đánh đồng giải mã ký tự với giải mã mật mã.
- `fetchall` gắn với SELECT trước đó trên đúng cursor; câu SQL sau hoặc nhánh không bảo đảm đi tới làm mất liên kết.
- Kết nối SMTP, yêu cầu STARTTLS, đăng nhập và gửi thư; không coi lời gọi là kết nối/gửi thành công khi chạy.
- MIME: đặt payload, mã hóa Base64 phần MIME, đính kèm và chuyển thông điệp thành chuỗi.

Wildcard import, thay binding, sửa alias hoặc đối tượng không được chứng minh khiến parser bỏ fact. Mỗi fact mang hash nguồn và các dòng import/binding/call. Host kiểm hash và đúng đoạn dẫn chứng trước khi chuyển cho SLM. Những kiểm tra này bảo vệ nguồn gốc dữ kiện; chúng không chứng minh upstream chứa dữ liệu bí mật hay luồng thu thập–gửi đã đầy đủ.

Truy vấn tìm kiếm có thể lấy cả tên hàm và lời gọi phương thức từ đoạn đã đọc; không lấy nội dung comment/string làm lệnh. Tìm kiếm vẫn là substring giới hạn trong VM. Model không có shell tự do.

## Tái lập thử nghiệm cũ

Thử nghiệm thao tác riêng ở [ATOMIC_REPORT_STAGE](ATOMIC_REPORT_STAGE.md) vẫn là ablation trên đặc trưng đã thu. `--measured-revision` dùng đủ 23 file host được đóng băng trong `eval/reproductions/operation-assertions-v1/source`, kiểm từng SHA-256 và import dưới namespace riêng. Việc sửa parser/reviewer hiện tại không âm thầm thay dependency của phép đo cũ. Bản operation reporter hiện tại là phiên bản 2; chưa thay luồng demo bằng ablation đó.

## Bằng chứng và giới hạn

[Kiểm source trong VM](../deliverables/real-demo-evidence/typed-operations-v4-real-source-check.json) tìm được 10 fact .NET và 39 fact Python trên source thật đã thu. [Kiểm đường truyền](../deliverables/real-demo-evidence/typed-operations-v4-delivery-check.json) chạy lại công cụ, dùng ID phiên mới và kiểm 7 tìm kiếm. Đây là kiểm parser/truyền chứng cứ, không phải accuracy của agent.

285 kiểm thử phần mềm đạt trên Windows trước lượt ReAct v9. Lượt đo được giữ nguyên source trong thời gian chạy. Các tiêu chí chưa đạt vẫn theo [PROJECT_GOAL](PROJECT_GOAL.md) và [CONG_VIEC_CON_LAI](CONG_VIEC_CON_LAI.md).

## Lượt ReAct v9: lỗi vẫn còn và được giữ lại

Run `20261127T230331_8bd30a1f` dùng Qwen3 8B, source `abaf6951…`, mất 495,9169 giây; 43 lần gọi model, 17 tool call, 4 backend phân tích thành công và 1 lỗi pycdc. Chương trình tiếp tục qua disassembly/literal decoder; không thực thi mẫu. [Receipt](../deliverables/real-demo-evidence/python2024-cards-v9-run.json).

[Audit đủ 18 câu thô](../eval/adjudications/python2024-cards-v9-full-audit.json) chấm 13 đúng/5 thiếu căn cứ. Reviewer giữ 14 câu, trong đó 11 đúng/3 thiếu căn cứ, đồng thời loại nhầm câu SMTP/đính kèm đúng. Precision theo câu là 72,22% raw và 78,57% sau lọc; tỉ lệ bịa lần lượt 27,78% và 21,43%. Không có câu ATT&CK. Các biểu thức đường dẫn có biến bị đưa thành IOC; một câu đọc file gán nhãn lớp API trừu tượng thành hàm được gọi. [Điểm theo câu](../deliverables/real-demo-evidence/python2024-cards-v9-claim-score.json). Tự duyệt cùng model chưa đủ tin cậy.

Để đo cả phần bỏ sót, [profile nguyên tử v2](../eval/reference_units/python2024.atomic-v2.json) giữ 29 đơn vị cũ và thêm 5 đơn vị download/autofill được đối chiếu source, tránh loại âm thầm những câu đúng ngoài phạm vi cũ. Profile được mở rộng **sau** lượt development này, không là test mù. Tách các câu nhiều thao tác tạo 22 đơn vị dự đoán: 17 đúng/5 thiếu căn cứ, phủ 17/34. **P 77,27%, R 50%, F1 60,71%; sau lọc P 81,25%, R 38,24%, F1 52%.** Đây là điểm theo đơn vị nguồn trong phạm vi công bố, khác mẫu số điểm theo câu bên trên; không trộn hai loại điểm. [Mapping đầy đủ](../eval/adjudications/python2024-cards-v9-atomic-mapping.json), [kết quả](../deliverables/real-demo-evidence/python2024-cards-v9-atomic-score.json).

```powershell
.\.venv\Scripts\python.exe scripts/record_card_v9_results.py
.\.venv\Scripts\python.exe scripts/record_card_v9_atomic.py
```

Hai lệnh này tái tính đúng lượt được khóa hash trên máy có nhật ký riêng; không chấm tự động một run mới và không tạo lại kết quả bằng mock. Thành viên chạy lại sẽ có run ID mới, cần lập nhãn đối chiếu riêng. Nhãn hiện tại là automated source audit, không giả xác nhận của người thật/GV.

## Sửa tiếp ở v10

`evidence-cards/10` giới hạn trường IOC bằng enum theo literal mạng nguyên vẹn trong đoạn đã chiếu. Nếu không có ứng viên, schema chỉ cho phép ATT&CK có căn cứ hoặc abstain; không thể chọn biểu thức đường dẫn làm IOC. Đây là ràng buộc từ vựng trên đặc trưng đã nhận, không phải đọc/chạy file mẫu ở host. Phạm vi còn hẹp: không giải escape, nội suy, nối chuỗi, URL chứa thông tin đăng nhập/query/fragment hoặc file path động. Thiếu ứng viên không chứng minh lành tính; lớp này chưa thay thế việc phân tích cấu hình đầy đủ.

Dữ kiện API gửi cho model dùng trường `api_semantics`; đọc/ghi file được diễn giải là phương thức trên đối tượng từ `open`, không khẳng định lớp cụ thể. Metadata gốc và hash vẫn giữ trong log. 318 kiểm thử phần mềm đã đạt trước lượt chạy v10. Việc sửa schema không tự chứng minh hết hallucination hoặc đạt Recall; phải đo lại report thực.

Lượt chạy từ đầu `20261127T231649_f3f05893` dừng sau 189,5665 giây vì RAM host trống chỉ còn 255.528.960 byte, thấp hơn ngưỡng bảo vệ. Có 13 model call, 13 tool call, 4 backend thành công; chưa tới bước báo cáo. Status `incomplete`, không có điểm chất lượng. Model đã được unload theo guard; ngưỡng không bị hạ. [Receipt lượt dở](../deliverables/real-demo-evidence/python2024-cards-v10-memory-stop.json). Sau đó VM được tắt để kiểm riêng phần báo cáo trên chứng cứ đã thu; phép thử riêng không thay demo từ đầu đến cuối.

## Kết quả v10 trên đúng các đoạn nguồn của v9

Run report `20261127T232149_05950420` dùng Qwen3 8B thật trên chứng cứ VM đã thu của v9. Hash các đoạn source/range khớp giữa hai phiên bản; chỉ so phần báo cáo, không lấy 202,5253 giây của phép thử này so với495,9169 giây đầu-cuối của v9. Có19 model call,30.692 prompt token,1.353 completion token; RAM trống nhỏ nhất giữa các request là1.318.670.336B. Snapshot24 file host `4fd36edf…`; bản core49 file tương ứng `7b5750b9…` đã đồng bộ VM trước lượt bị dừng. [Receipt và hash](../deliverables/real-demo-evidence/python2024-cards-v10-report-stage-run.json).

Đối chiếu đủ12 câu raw: **12 đúng/0 sai/0 thiếu căn cứ** trong phạm vi source đã đưa. Có11 hành vi và1 hostname IOC, không có ATT&CK. Lỗi IOC biểu thức và lớp API thành hàm gọi không tái xuất hiện. Reviewer vẫn loại nhầm2 câu đúng: chuỗi archive/attachment/SMTP và DPAPI. Verdict sau kiểm là `suspicious`, chưa đúng nhãn malicious của mẫu. Đây là12 câu của một mẫu development, không phải precision toàn corpus hay đảm bảo0% hallucination cho những lần chạy khác. [Audit](../eval/adjudications/python2024-cards-v10-report-stage-audit.json), [điểm theo câu](../deliverables/real-demo-evidence/python2024-cards-v10-report-stage-claim-score.json).

| Đơn vị đo trên cùng profile34 | V9 raw | V10 report raw | V10 sau lọc |
|---|---:|---:|---:|
| Đơn vị đúng / dự đoán |17/22|15/15|11/11|
| Precision |77,27%|100%|100%|
| Recall |50%|44,12%|32,35%|
| F1 |60,71%|61,22%|48,89%|
| Đơn vị còn thiếu |17|19|23|

[Mapping v10](../eval/adjudications/python2024-cards-v10-report-stage-atomic-mapping.json) và [điểm nguyên tử](../deliverables/real-demo-evidence/python2024-cards-v10-report-stage-atomic-score.json) giữ mọi câu bị loại. Ràng buộc mới giúp bỏ câu sai nhưng độ phủ giảm; không kết luận toàn hệ thống đã tốt hơn hoặc đạt tiêu chí. Cần mở rộng độ phủ thao tác/luồng và xử lý false rejection, đồng thời đo ATT&CK/verdict trên cả hai nhánh.

Tái tính lượt được khóa hash: `python scripts/record_card_v10_results.py`. Muốn chạy model lại trên nhật ký riêng: `python scripts/replay_card_report.py --run 20261127T230331_8bd30a1f --config config/host.cards-qwen3-candidate.example.json --cards 10`. Đây luôn là phép thử report trên chứng cứ thật đã thu, không phải demo VM mới. Một run mới cần source audit mới; không sao chép nhãn theo vị trí câu.

Sau đợt đo, [receipt dừng runtime](../deliverables/real-demo-evidence/runtime-stopped-after-cards-v10.json) xác nhận process Ollama dự án không còn,0 listener ở11435,0 VMware VM đang chạy, GPU toàn máy0MiB tại lúc kiểm. Không xóa weights/đĩa VM và không dừng ứng dụng không liên quan.
