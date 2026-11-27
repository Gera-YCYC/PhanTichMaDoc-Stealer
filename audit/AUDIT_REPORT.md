# Đánh giá repo PhanTichMaDoc-Stealer theo yêu cầu đồ án

Ngày kiểm tra: **27/11/2026**. Repo: <https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer>.
Commit được kiểm tra: **9362d1c0c8455bb15ff089c4b7c0bbc5b0f356f4** (`main`, commit ngày 22/11/2026).
HEAD từ remote được hỏi lại sau kiểm tra và vẫn trùng commit này.

## 1. Kết luận để quyết định

**Repo đúng hướng đề tài và có các thành phần triển khai thật, nhưng chưa đủ đáng tin để dùng nguyên trạng làm bản nộp hoặc tuyên bố đã đạt buổi 4.** Có thể dùng làm nguồn tham khảo và giữ lại những module qua được kiểm thử; cần sửa trọng tâm phần kiểm chứng nhận định, xử lý lỗi, ranh giới VM và bằng chứng chạy SLM thật.

Không có cơ sở nói toàn bộ repo là giả: vòng lặp ReAct có gọi client Ollama, tra registry và thực thi hàm công cụ; có parser, cơ chế sửa phản hồi sai định dạng, giới hạn vòng lặp, wrapper .NET/PyInstaller và xuất báo cáo. Nhưng tính đúng của kết luận chưa được bảo vệ bởi các kiểm tra bắt buộc.

**Khuyến nghị:** làm bản dự án do nhóm kiểm soát từ yêu cầu của giảng viên; tái sử dụng có chọn lọc cách tính hash/entropy, nhận diện định dạng, AST và khung wrapper. Viết lại hoặc sửa sâu điều phối, schema bằng chứng, nhật ký và chính sách công cụ. Chưa có lý do kỹ thuật để vứt bỏ toàn bộ công sức hiện có, cũng chưa có cơ sở để tin các báo cáo hiện tại là kết quả đánh giá chất lượng agent.

## 2. Phạm vi và cách kiểm chứng

- Đọc cây Git gồm 27 file; kiểm tra cú pháp 16 file Python, tổng 3.207 dòng.
- Đọc mã nguồn agent, tools, reporting, cấu hình, Docker, luật YARA, hướng dẫn và hai báo cáo được commit.
- Chạy **14 phép kiểm tra** trong `review_checks.py`, bằng dữ liệu tổng hợp/lành tính và phản hồi mô hình có kịch bản. Kết quả gốc: [review-results.json](evidence/review-results.json).
- Bộ kiểm tra chặn khởi tạo subprocess và các lời gọi HTTP của repo. File `samples/benign_stealer_sim.py` chỉ được đọc như dữ liệu để phân tích tĩnh, không import hoặc thực thi file mẫu.
- Tạo DLL dữ liệu lành tính từ [BenignReviewFixture.cs](synthetic-inputs/BenignReviewFixture.cs) bằng trình biên dịch C# có sẵn; chỉ đọc metadata, không thực thi DLL.
- Chạy YARA thật 4.5.4 trên một file văn bản tổng hợp để đối chiếu fallback; kiểm tra dnfile 0.17.0 trên DLL lành tính. Các gói kiểm thử nằm riêng ở `audit/review-deps/`, không cài đè Python toàn máy.
- Có phép đối chứng chạy vòng agent với `DeterministicMockLLM`: gọi thành công ba hàm phân tích tĩnh trên fixture, rồi xuất `Final Answer`. Đây là kiểm thử phần mềm, **không phải chứng nhận demo trong VM hay SLM thật**.
- Không chạy mẫu mã độc; chưa có mẫu I/J của GV; không khởi động/sửa VM; chưa chạy SLM 7B; chưa build Docker do môi trường không có Docker CLI. Không sửa, commit hay push repo được kiểm tra.

Môi trường kiểm thử: Python 3.11.9, requests 2.32.5, pydantic 2.8.2, yara-python 4.5.4, pefile 2024.8.26, dnfile 0.17.0.

## 3. Phát hiện cần sửa trước demo

### R01 — Chấp nhận kết luận khi chưa gọi công cụ — Cao, đã tái hiện

`agent/react_engine.py:396–411` chấp nhận `Final Answer` sau khi schema hợp lệ, không yêu cầu bất kỳ công cụ thành công nào. Lời nhắc trong prompt yêu cầu nhận diện và quét IOC không được thực thi bằng điều kiện trong code.

Ca `early_final_without_tools`: số tool chạy **0**, kết quả **BENIGN**, confidence **HIGH**, trạng thái **completed**.

Ảnh hưởng: không chứng minh mốc buổi 4; kết luận có thể hoàn toàn thiếu dữ liệu. Cần điều kiện hoàn tất dựa vào tool thành công và phạm vi bằng chứng; thiếu dữ liệu phải là `inconclusive`/`incomplete`.

### R02 — Công cụ lỗi có thể dẫn tới kết luận lành tính — Cao, đã tái hiện

`agent/react_engine.py:658–689` tính verdict từ điểm mặc định 0 nếu không có bằng chứng. Dữ liệu thiếu do lỗi không được phân biệt với kết quả phân tích sạch.

Ca `failed_analysis_becomes_benign`: tool nhận diện trả lỗi tổng hợp, mô hình trả sai định dạng, kết quả cuối **completed_with_fallback / BENIGN / MEDIUM**, hashes rỗng.

Cần trạng thái lỗi/thiếu bằng chứng rõ ràng; không quy đổi lỗi, thiếu tool, timeout hoặc thiếu output thành âm tính.

### R03 — Không kiểm chứng IOC/ATT&CK do mô hình tạo — Cao, đã tái hiện

`agent/react_engine.py:45–63` cho phép evidence là chuỗi tự do; `:603–654` bắt đầu bằng các IOC/ATT&CK từ mô hình rồi thêm kết quả tool. Đây là phép hợp nhất, không phải bộ xác minh nhận định.

Ca `fabricated_findings_survive`: URL tổng hợp không xuất hiện trong bất kỳ Observation nào và mã **T9999.999** đều còn trong báo cáo `completed`.

Cần claim ID, tool-call ID, nguồn, dòng/offset và quote/value đối chiếu được; ATT&CK phải có trong danh mục chuẩn và được hỗ trợ bởi hành vi. Xác nhận quote tồn tại chỉ là kiểm chứng dẫn chứng, vẫn cần kiểm tra nhận định có suy diễn quá mức không.

### R04 — Cắt gọn output có thể làm agent crash — Cao, đã tái hiện

`tools/utils.py:120–123` thêm chuỗi thông báo cắt gọn vào danh sách vốn chứa dict. `agent/react_engine.py:593–600` gọi `.get()` trên từng phần tử danh sách kết quả YARA mà không kiểm tra kiểu.

Ca `truncated_observation_crashes_agent`: JSON hợp lệ, dài 2.917 ký tự sau cắt gọn, nhưng agent dừng với **AttributeError: 'str' object has no attribute 'get'**.

Cần metadata cắt gọn đặt ngoài danh sách dữ liệu, schema cố định, kiểm tra kiểu tại mọi biên và lưu bản đầy đủ để truy xuất bằng chứng.

### R05 — Cô lập chưa đáp ứng được bằng chứng yêu cầu trên slide — Cao, đọc mã + thử đường dẫn

`main.py:170–179` chạy agent tại chỗ và `agent/react_engine.py:541–549` gọi hàm tool trực tiếp trong cùng tiến trình. Không có tool server qua VM hay chốt từ chối chạy công cụ trên host. Hướng dẫn có khuyến cáo Docker/VM cho mẫu thật nhưng chưa cưỡng chế bằng code.

`docker-compose.yml` có non-root, bỏ capabilities, hạn RAM/CPU, mount mẫu read-only: đây là các điểm tốt. Tuy nhiên cấu hình không có mạng nội bộ hạn chế egress, không có firewall chỉ cho kết nối SLM và không chứng minh snapshot/network/clipboard của VM lab. Docker có thể đặt **bên trong VM cô lập**, nhưng cấu hình hiện tại chưa chứng minh điều đó.

`tools/utils.py:25–34` chỉ kiểm tra file tồn tại, không giới hạn vào thư mục mẫu. Ca `path_not_confined_to_samples` chấp nhận file tổng hợp nằm ngoài `repo/samples`. `ast_python_scanner` cũng nhận đường dẫn tự do hoặc source inline; dữ liệu inline không tự chứng minh xuất phát từ mẫu.

Cần xác lập ranh giới VM; allowlist sample ID; resolve và kiểm tra containment; kiểm tra đường dẫn output; cơ chế gọi công cụ xác thực; hạn mạng. Không coi tên hàm trong whitelist là đủ để bảo vệ dữ liệu.

### R06 — Chưa có lớp chống prompt injection và bộ thử — Cao về yêu cầu đồ án

`agent/react_engine.py:444` đưa Observation vào message có role `user`; system prompt chưa xác định rõ nội dung mẫu là dữ liệu không đáng tin. Không tìm thấy guard chuyên dụng hay bộ ≥10 file injection.

Ca `injection_text_forwarded_without_guard` chứng minh chuỗi chỉ thị tổng hợp được chuyển nguyên văn tới client. **Ca này không đo tỷ lệ mô hình thực sự bị lừa**; chưa có quyền kết luận tỷ lệ 0% hay 100%.

Cần phân tách dữ liệu và chỉ thị, kiểm tra hành động bằng code, kiểm chứng kết luận, bộ thử cả chiều báo lành và báo độc sai. Regex đơn lẻ không đủ làm bằng chứng an toàn.

## 4. Phát hiện về tool, độ tái lập và đánh giá

### R07 — Hai báo cáo hiện có là mock và YARA fallback

Cả `reports/benign_stealer_sim_20261121_100226.json` và `...100633.json` đều ghi **model_name = mock-slm-react-v1**; Observation quét luật ghi **engine = builtin_fallback**. Chúng ghi rõ chế độ mock, không có căn cứ quy kết tác giả cố che giấu.

Đây là bằng chứng chạy luồng kiểm thử, không chứng minh Ollama/SLM 7B, ILSpy, pyinstxtractor, pycdc hay YARA thật chạy thành công. Hai báo cáo đều phân tích cùng một fixture Python, chưa phải mẫu I/J.

### R08 — Fallback không tương đương YARA thật — Vừa, đã tái hiện

`tools/ioc_yara_scanner.py:116–145` dùng điều kiện chuỗi đơn giản khác với `rules/infostealer_rules.yar:30–46`.

Ca `fallback_yara_semantics_differ`: file văn bản chỉ chứa `discord.com/api/webhooks` bị fallback báo trúng `InfoStealer_Session_Discord_Telegram`, trong khi **YARA thật 4.5.4 với chính file luật của repo không trúng luật nào**.

Không được dùng số hit của fallback để công bố TPR/FPR của YARA. Agent cũng chỉ **quét luật có sẵn**, chưa có hành động sinh luật, biên dịch luật vừa sinh và vòng sửa dựa trên bộ độc/sạch.

### R09 — Thiếu công cụ .NET vẫn báo ok — Vừa, đã tái hiện

`tools/dotnet_analyzer.py:95–96`, `:196–198`, `:274–281` cho phép thiếu cả dnfile và ilspycmd nhưng status tổng vẫn `ok`. Ca `missing_dotnet_tools_report_ok` tái hiện điều này trên file văn bản lành tính.

Ca đối chứng đọc metadata bằng dnfile thật có lấy được tên assembly và một chuỗi trong DLL dữ liệu. Điều đó chỉ chứng minh nhánh metadata này hoạt động trên fixture, **không chứng minh ILSpy dịch ngược thành công**.

Cần phân biệt `ok`, `partial`, `unavailable`, `unsupported`, `error` theo từng backend; chỉ đếm tool thật khi backend thật đã thành công.

### R10 — Trích IOC còn bỏ sót UTF-16 — Vừa, đã tái hiện

`tools/ioc_yara_scanner.py:164–169` chỉ chạy bộ trích printable strings nếu decode UTF-8 thất bại. Chuỗi UTF-16LE chứa ASCII và byte NUL vẫn decode UTF-8 được, khiến đường trích UTF-16 không chạy.

Ca `utf16_ioc_omitted_when_utf8_decode_succeeds`: URL `https://indicator.invalid/path` ở dạng UTF-16LE bị bỏ sót, `iocs = {}`. Cần chạy các bộ trích mã hóa phù hợp độc lập, lưu offset và chống trùng.

### R11 — Build Docker không khóa phiên bản, có xung đột .NET/ILSpy — Xác minh cấu hình và nguồn chính thức

Dockerfile cài **.NET SDK 8**, rồi `dotnet tool install --global ilspycmd` không khóa phiên bản. Tại ngày kiểm tra, NuGet liệt kê bản ổn định mới nhất **11.2.0.10050**; tài liệu gói yêu cầu **SDK ≥10.0.100 để cài đặt/cập nhật**.

Đây là xung đột được xác định từ cấu hình và yêu cầu chính thức, **chưa phải log build Docker thất bại**. Cần khóa bộ phiên bản tương thích rồi build sạch và lưu log. Nguồn: [ilspycmd 11.2.0.10050 trên NuGet](https://www.nuget.org/packages/ilspycmd/11.2.0.10050).

### R12 — Chưa có bộ đánh giá theo giảng viên; nhật ký chưa đầy đủ

Không thấy tests/evaluation/ground truth/12 injection fixtures/CI trong cây Git. Không có phép tính Precision, Recall, F1, tỷ lệ bịa, grounding, stability 3 lần, TPR/FPR hay bảng từng nhận định so với đáp án GV.

Hiện có `reasoning_trace` trong report, số bước, số lần sửa và thời gian tổng: hữu ích nhưng thiếu log append ngay sau từng bước, input/output thô đầy đủ, thông tin phiên bản/backend, token/RAM/VRAM và đáp án đối chiếu. `main.py:184` chỉ ghi report sau khi `analyze()` hoàn tất; khi crash, chưa có nhật ký bền vững đầy đủ.

Điểm AST và confidence đang là heuristic, không phải các chỉ số chấm của giảng viên. Ca `benign_json_parse_labeled_dangerous` cho thấy `json.loads("[]")` bị ghi là dangerous call và cộng 10 điểm. Cần tách dấu hiệu cú pháp khỏi kết luận hành vi thực sự.

### R13 — Báo cáo chưa che token; Git chưa chặn mẫu thật — Vừa

`reporting/report_generator.py:57–64` ghi nguyên IOC, kể cả token; `:151–153` ghi toàn bộ dữ liệu JSON. Ca `report_exposes_full_token` dùng token giả xác nhận không có bước che dữ liệu. `.gitignore` chưa chặn `samples/`, binary mẫu hoặc báo cáo riêng tư.

Repo hiện chỉ có fixture được khai báo giả lập; **không phát hiện hay cáo buộc có token thật/mẫu độc thật bị lộ**. Cần bản raw riêng trong VM và bản xuất nộp đã che; tránh commit dữ liệu mẫu thật về sau.

## 5. Đối chiếu các mốc

| Yêu cầu | Hiện trạng | Kết luận |
|---|---|---|
| Đúng Hướng 6: .NET/Python stealer | Có wrapper cho hai nhánh, IOC/webhook/token | Đúng hướng |
| Vòng ReAct | Có client Ollama, parser, dispatch, observation và vòng lặp | Có triển khai; cần sửa chốt hoàn tất |
| Buổi 4: agent gọi ≥2 tool | Đối chứng mock gọi 3 hàm tĩnh; chưa có log SLM thật trong VM | Chưa xác nhận đạt |
| Mẫu I và J | Chỉ có fixture Python nguồn | Chưa kiểm chứng trên mẫu GV |
| SLM 7B của hướng 6 | Cấu hình mặc định 7B; báo cáo hiện tại mock | Chưa có bằng chứng chạy |
| Không chạy công cụ ngoài VM cô lập | Có Docker tùy chọn; không có chốt host/VM hay bằng chứng cấu hình lab | Cần sửa và kiểm chứng |
| Nhật ký thật | Trace trong report mock; lưu sau cùng | Có nền, chưa đủ gói bằng chứng |
| Grounding/hallucination | Chưa có validator thực chất | Chưa đạt mục tiêu kiểm soát |
| YARA do agent sinh + TPR/FPR | Chỉ có luật tĩnh và scan/fallback | Chưa triển khai đủ |
| Buổi 6: ≥3 mẫu có nhật ký | Hai report cùng một fixture | Chưa có bằng chứng đạt |
| Buổi 8: đầy đủ + bảng đánh giá | Không có bộ đo theo đáp án GV | Chưa hoàn chỉnh |

Không chấm điểm số thay giảng viên. 14 phép thử kỹ thuật ở đây không thay bộ mẫu/đáp án GV và không được quy thành F1 hay tỷ lệ an toàn.

## 6. Phần nên giữ và thứ tự sửa

**Có thể giữ sau kiểm thử:** bố cục module, tính hash/entropy, ý tưởng nhận diện file, cách gọi CLI không shell và có timeout, AST scanner như công cụ thu đặc trưng, regex IOC như bộ ứng viên, cấu trúc xuất JSON/Markdown, mock client để chạy unit test.

**Cần sửa trước buổi 4:**

1. Chốt VM cô lập và đường dẫn mẫu; tool execution trong VM, SLM ở host; lưu bằng chứng mạng/snapshot.
2. Chốt hai tool phục vụ demo .NET: nhận diện bằng pefile/DIE và dịch ngược bằng ILSpy; thiếu backend phải báo lỗi rõ.
3. Chặn Final Answer nếu chưa đủ tool thành công; thêm verdict `inconclusive` khi thiếu dữ liệu; kiểm chứng từng IOC/nhận định.
4. Sửa cắt gọn dữ liệu, lưu output đầy đủ và nhật ký JSONL ngay từng bước; bổ sung test cho mọi lỗi đã tái hiện.
5. Chạy Ollama với mô hình đáp ứng hướng 6, lưu phiên bản/digest/model options và log chạy; đo thời gian/tokens.
6. Dùng fixture lành tính để kiểm tra lắp ráp; xin mẫu I/J từ GV để có demo trên đúng dữ liệu môn học. Nếu dùng fixture thay ở buổi 4 thì phải được GV chấp nhận, không tự coi là mẫu I.

**Sau đó, buổi 6–8:** hoàn thiện PyInstaller/pycdc theo phiên bản Python; bổ sung mẫu thứ ba theo xác nhận GV; sinh/kiểm YARA trên bộ độc/sạch riêng; bộ injection ≥10 file; ground truth và chấm từng nhận định; chạy lặp ba lần; báo cáo, slide/video và phân công thành viên.

## 7. Tái chạy kiểm tra

Tại thư mục gốc workspace:

```powershell
python -m pip install --target audit/review-deps --only-binary=:all: yara-python==4.5.4 pefile==2024.8.26 dnfile==0.17.0
& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /nologo /target:library /out:.\audit\synthetic-inputs\BenignReviewFixture.dll .\audit\synthetic-inputs\BenignReviewFixture.cs
python audit/review_checks.py
```

Python cần có `requests` và `pydantic` v2 như bảng môi trường. Script không sửa mã nguồn `friend-repo`. Nó tái tạo file văn bản/DLL dùng thử và ghi đè **chỉ các kết quả kiểm tra của audit**.

Các artifact:

- [Script tái hiện](review_checks.py)
- [Kết quả 14 phép kiểm tra](evidence/review-results.json)
- [Log console](evidence/review-console.txt)
- [Kết quả vòng chạy mock đối chứng](evidence/mock-control-run.json)
- [Cảnh báo dnfile trên fixture](evidence/dnfile-fixture-warnings.log)
- [Bản clone giữ nguyên commit](friend-repo/README.md)

Đánh giá này chỉ áp dụng cho commit nêu trên; thay đổi sau đó cần kiểm tra lại.
