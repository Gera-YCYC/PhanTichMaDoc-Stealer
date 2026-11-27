# Sinh và kiểm YARA trên mẫu thật

Luồng `stealer_agent.yara_corpus` là giai đoạn phát hiện riêng của sản phẩm. Nó dùng SLM cục bộ để chọn chuỗi/điều kiện, gọi công cụ thật trong VM, nhận kết quả và sửa tối đa bốn lần cho mỗi mẫu. Nó không lấy kết quả YARA để thay cho phân tích hành vi, ATT&CK hoặc verdict của báo cáo.

## Dữ liệu và phạm vi kết luận

`eval/corpora/real-yara-v1.json` khóa năm mẫu độc public dùng phát triển và tám file sạch có chữ ký Microsoft. Profile `real-v1` trỏ đến manifest riêng trong VM. Profile `fixture` lịch sử vẫn còn và không được dùng để tính kết quả bộ thật. Nếu profile thật thiếu hoặc hash khác, chương trình từ chối chạy, không tự chuyển sang fixture.

- `training`: năm mẫu độc đã được xem trong quá trình phát triển. Tên partition này chỉ nói về dữ liệu tinh chỉnh luật; **không có nghĩa cập nhật trọng số Qwen**.
- `holdout`: tám file sạch, dùng sau khi cố định luật. Phần này không có mẫu độc nên TPR holdout là `null`.
- TPR trên development và FPR trên clean holdout được ghi riêng, kèm mẫu số, từng hash và kết quả khớp. Không ghép chúng thành kết luận về độ chính xác trên mọi stealer chưa thấy.
- Đề xuất gốc dự kiến khoảng 30–50 file sạch, gồm .NET và Python/PyInstaller. Bộ v1 chỉ có tám file. Bộ v2 mở rộng lên 38 file đã tìm thấy báo nhầm; bộ v3 có tổng cộng 39 file sạch ở hai partition, gồm 37 tiện ích Microsoft và hai ứng dụng PyInstaller chính thức.

`real-yara-challenge-v2.json` giữ lần kiểm bộ luật v1 không sửa: **1/38 báo nhầm**, chính là yt-dlp 2024.08.06. Sau đó `real-yara-development-v3.json` chuyển yt-dlp sang development cùng năm mẫu độc, giữ 37 file Microsoft ở partition `holdout` và thêm gallery-dl 1.27.5. Tên `holdout` là tên kỹ thuật; 37 file đã từng được kiểm, và gallery-dl chỉ mới ở lần v3 đầu. Các lần chạy v3 sau đó là kiểm hồi quy trên corpus đã biết, không được gọi là phép thử mù mới.

Hai ứng dụng được tải từ Release chính thức và khóa SHA256. yt-dlp còn đối chiếu checksum do dự án công bố; chữ ký GPG của hai dự án chưa được xác minh. Đây là nhãn ứng dụng hợp lệ kỳ vọng không phải stealer, không có nghĩa mọi cách sử dụng chúng đều lành tính. File không được thực thi.

## Luồng chạy

1. Kiểm VM cô lập, metadata model và hash corpus giữa host/VM.
2. Với mỗi mẫu development, tool `yara_candidates` quét chuỗi ASCII/UTF-16LE trong **byte gốc** và trả tối đa 60 ứng viên có offset/encoding. Bản `/2` đọc thêm TOC CArchive có kiểm bounds để tìm tên entry chương trình, phân biệt với hook `pyi_rth_*` và `pyiboot*`. Không giải nén hay thực thi mẫu trong bước này.
3. Host loại các ứng viên bị bộ lọc credential/instruction nhận diện; đưa tối đa 30 ứng viên, giới hạn 6.000 ký tự, vào model. Không dùng placeholder đã che làm chuỗi phát hiện.
4. Model chọn 2–6 ID chuỗi và điều kiện `all` hoặc `at_least_two`. Controller render cú pháp, thêm PE magic và giới hạn 32.000.000 byte; không tự chọn chuỗi thay model. Chuỗi trùng bị từ chối. Với `2 of`, hai chuỗi lồng nhau bị từ chối vì một tín hiệu có thể thỏa hai điều kiện. Với `all`, cho phép một chuỗi thừa nếu vẫn có ít nhất hai chuỗi tối đại độc lập; bản trước đã chặn quá mức trường hợp này. Nếu có entry chương trình PyInstaller, model phải chọn ít nhất một, và điều kiện bắt buộc entry đó cùng các chuỗi khác. Đây là chỉ dấu của bản build, không phải chứng minh hành vi.
5. VM compile chính luật đó bằng YARA và quét tập development. Nếu mục tiêu chưa khớp, luật lỗi hoặc trúng file sạch development, agent nhận feedback và có thể chọn lại. Không dùng hash toàn file hoặc chuỗi marker đồ chơi làm điều kiện.
6. Gộp các luật, ghi `generated.yar` và sự kiện `rules_frozen`. Quét development, rồi clean holdout. Sau đó worker mới compile lại và quét lại cùng byte/manifest/luật để đối chiếu; không còn lời gọi model sau khi cố định luật.

Chuỗi có trong binary chỉ chứng minh sự hiện diện. Đặc biệt PyInstaller chứa nhiều thư viện bình thường; luật chỉ dựa vào `sqlite`, `crypto`, tên `.pyd` có thể báo nhầm ứng dụng sạch. Vì vậy kết quả đạt ngưỡng trên bộ nhỏ vẫn chưa đóng nghiệm thu toàn đồ án. Payload được nén có thể không để lộ chuỗi hành vi trong file gốc; luật này công bố rõ representation, không giả vờ quét mã đã giải mã.

## Chạy lại trên máy đã cài lab và nhập corpus

Từ thư mục gốc dự án trong PowerShell:

```powershell
.\scripts\Start-Lab.ps1
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/enable_real_yara.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
.\scripts\Run-YaraCorpus.ps1 -Profile candidate-8b -CorpusProfile real-v1
.\scripts\Stop-Lab.ps1
```

Chạy từng lệnh và kiểm thành công trước lệnh tiếp theo. Nếu VM đang khởi động và SSH chưa sẵn sàng, đợi VM lên rồi chạy lại Start-Lab; không tiếp tục sync khi Start-Lab còn lỗi. Lệnh đăng ký corpus chỉ dùng manifest đã nhập, không tải mẫu hoặc đổi cấu hình mạng.

`candidate-8b` yêu cầu `qwen3:8b` đã cài cục bộ. `-Profile baseline` dùng Qwen2.5-Coder 7B đang phát hành. Script không tải model thay thế âm thầm. Bộ model Release vẫn giữ nguyên; so sánh kết quả phải ghi rõ tag/digest/config.

Trước lần chạy đầu, theo [chuẩn bị corpus](CLEAN_CORPUS.md). Hash file Windows khác giữa các máy/bản cập nhật thì phải tạo phiên bản lock mới; không sửa kết quả cũ để khớp máy mới.

Chuẩn bị và chạy bộ mở rộng v3 (sau bước nhập v1):

```powershell
.\scripts\prepare_clean_challenge.ps1
.\.venv\Scripts\python.exe scripts/lock_clean_challenge.py
.\.venv\Scripts\python.exe scripts/import_clean_challenge.py
.\.venv\Scripts\python.exe scripts/prepare_yara_v3.py
.\.venv\Scripts\python.exe scripts/enable_real_yara.py --profile real-v3
.\scripts\Run-YaraCorpus.ps1 -Profile baseline -CorpusProfile real-v3
```

`prepare_clean_challenge.ps1` cố ý dừng nếu manifest đã tồn tại để giữ lần thu trước. Các bước tiếp theo xác minh file đang có, không yêu cầu tải lại. `baseline` ở luồng YARA dùng config riêng context 4096/seed 42/num_predict 1800 để so với 8B; không đổi cấu hình phân tích hành vi mặc định. Cả hai model đều có nhật ký riêng.

Để kiểm lại bộ luật cũ trên challenge v2 mà không gọi model:

```powershell
.\.venv\Scripts\python.exe scripts/evaluate_frozen_yara.py runs/<yara-run-id>
```

Lệnh yêu cầu luật đúng hash ở sự kiện `rules_frozen`, chạy worker YARA với user `analyst`, so kết quả hai tiến trình độc lập. Không sửa luật hay gọi model. Với luật được chỉnh sau khi đã thấy challenge v2, kết quả này chỉ là hồi quy.

## Bằng chứng và tái lập

### Kết quả thật ngày 28/11/2026

| Đợt | Phát hiện development | Báo nhầm sạch | Ý nghĩa |
|---|---:|---:|---|
| v1, 8B `14243d3cbc98` | 5/5 | 0/8 | Bộ âm tính quá hẹp |
| Giữ nguyên luật v1, challenge v2 | 5/5 từ đợt gốc | **1/38** | yt-dlp bị hai luật Python báo nhầm; chưa đạt FPR=0 |
| TOC + luật cũ kiểm chuỗi quá chặt, 8B `eb3b4bd0b1cc` | 4/5 | 0/39 | Mercurial bị chặn; không đạt TPR90% |
| Cùng bản kiểm quá chặt, 7B `5670f319fdab` | 4/5 | 0/39 | Xác nhận lỗi controller ảnh hưởng cả hai model |
| Bản sửa, 7B `67d77a7d68ac` | **5/5** | **0/39** | 42,5242s, 5 model call, 14 tool call không tính paging |
| Cùng bản sửa, 8B `4054c42e1321` | **5/5** | **0/39** | 73,0389s, 5 model call, 14 tool call không tính paging |

Hai lượt cuối dùng cùng snapshot `66ec53b440f7dbb2e21784c4d8fde982122282af01b24aae6c679503985cd659`, context 4096, seed42, num_predict1800. 8B có `think=false`. Cả hai có replay bằng tiến trình YARA mới cho kết quả trùng, không lỗi tool, không có request model sau freeze. 7B dùng 6.247 prompt/394 completion token; 8B dùng 6.287/485. Đây là hai phép đo đơn trên cùng máy, không phải benchmark tốc độ có nhiều lần lặp.

Receipt và nhật ký metadata: [7B](../deliverables/real-demo-evidence/yara-runs/yara_real_67d77a7d68ac/receipt.json), [8B](../deliverables/real-demo-evidence/yara-runs/yara_real_4054c42e1321/receipt.json). Luật chính xác: [7B](../rules/yara-v3-qwen7b.yar), [8B](../rules/yara-v3-qwen8b.yar). Luật v1 có báo nhầm được giữ [tại đây](../rules/yara-v1-observed-false-positive.yar).

Ngưỡng YARA **đạt trên bộ đã công bố**: TPR development100% và FPR toàn bộ39negative0%. Chỉ có năm positive, đều đã dùng phát triển; không gọi đây là TPR trên mã độc mới. Tên entry và tên executable đóng góp lớn vào luật nên thay tên/repack có thể làm mất phát hiện. Chưa có kiểm biến thể đổi tên; chưa đạt toàn bộ đồ án vì chất lượng hành vi/IOC/ATT&CK, ổn định và injection còn mở. Model7B được giữ làm lựa chọn mặc định cho luồng YARA vì có sẵn trong Release và lượt này đạt cùng ngưỡng với thời gian thấp hơn; không suy rằng 7B tốt hơn cho mọi phần của agent.

Mỗi lần chạy tạo `runs/yara_real_<id>/` chứa nhật ký hash-chain, nguyên messages/schema gửi model, phản hồi, kết quả tool phân trang, lựa chọn chuỗi, luật đã cố định và `summary.private.json`. Hash từng source Python, config, model digest, sample/rule/corpus hash được lưu. Bộ đếm tool không tính các lời gọi đọc trang; log vẫn giữ các trang đó. RAM là tiến trình điều phối host; VRAM là snapshot theo model, không phải peak tổng của máy.

Raw log và chuỗi chọn từ mẫu giữ cục bộ cho tới khi được kiểm tra trước xuất bản. Git chỉ nhận receipt cho phép công khai. `coursework_accepted` luôn false ở giai đoạn này vì các gate hành vi, độ tin cậy, độ phủ dữ liệu và injection còn phải đánh giá riêng.

API compile/match, timeout và chặn include theo [tài liệu yara-python](https://yara.readthedocs.io/en/stable/yarapython.html). Cú pháp chuỗi ASCII/wide, điều kiện đếm và filesize theo [tài liệu luật YARA](https://yara.readthedocs.io/en/stable/writingrules.html). Phiên bản backend thực tế được ghi trong từng kết quả VM.

Định dạng cookie/TOC theo [PyInstaller CArchiveReader v6.7.0](https://github.com/pyinstaller/pyinstaller/blob/v6.7.0/PyInstaller/archive/readers.py). Nguồn build ứng dụng sạch: [yt-dlp 2024.08.06](https://github.com/yt-dlp/yt-dlp/blob/2024.08.06/.github/workflows/build.yml), [gallery-dl 1.27.5](https://github.com/mikf/gallery-dl/blob/v1.27.5/.github/workflows/executables.yml). Parser tự viết chỉ đọc metadata có giới hạn, không import thư viện từ mẫu.
