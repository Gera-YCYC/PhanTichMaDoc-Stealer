# Thực nghiệm train bộ xếp hạng chứng cứ

Demo web hiện chạy Qwen3 8B bằng Ollama. Qwen dùng trọng số đã tải. Thành phần nhóm đã trực tiếp train là bộ xếp hạng chứng cứ dùng trong truy vấn mã. Trên web, **Gán nhãn** lưu nhận xét sau khi người dùng kiểm tra nguồn. Git có mã train, đặc trưng, cách chia dữ liệu và bước CI tái tạo checkpoint. [Cách dùng nhãn mới](../docs/WEB_DIEU_TRA.md#huấn-luyện-từ-nhận-xét)

Đây là **một lần train thật mô hình ML phụ trợ**, không phải fine-tune Qwen. Qwen2.5 Coder 7B vẫn dùng trọng số upstream. Loại train GV yêu cầu chưa rõ; thực nghiệm này không tự chứng minh GV chấp nhận thay fine-tuning SLM.

## Vì sao cần thành phần này?

Tìm chuỗi theo lần xuất hiện đầu tiên thường trả về khai báo hàm, bảng Names/Constants hoặc import. Agent cần tìm tới nơi tham chiếu mã thực tế trước khi kiểm tra hành vi. Bộ xếp hạng chỉ ưu tiên điểm tham chiếu; điểm cao không chứng minh mã độc, truyền dữ liệu, khả năng chạy hay một kỹ thuật ATT&CK.

Mô hình logistic regression có 13 trọng số và một bias. Feature gồm vị trí truy vấn trong mã/literal, dạng lời gọi, phép gán, opcode, import, bảng tên, khai báo và cấu trúc lân cận. Không dùng hash mẫu, tên family, nhãn độc/lành hoặc endpoint làm feature. Code suy luận ở [code_search.py](../vm_tools/code_search.py); checkpoint JSON ở [code_ranker.json](../vm_tools/code_ranker.json).

## Dữ liệu và giới hạn nhãn

[Corpus đã khóa](corpus/code-reference-v1.json) có 117 anchor từ ILSpy/pycdas trên bốn mẫu public thật. Mỗi anchor có hash mẫu, hash output, số dòng và hash nội dung dòng. Chỉ vector số và provenance được đưa lên Git; không xuất toàn bộ code hay khóa trong mẫu.

Nhãn là **chú giải cấu trúc tự động từ output công cụ**, không do người thật ký duyệt, không phải đáp án GV. Ví dụ, `SendMessage(...)` là tham chiếu thực, còn khai báo `extern SendMessage` và tham số `sender` không là điểm thực thi cần ưu tiên. Một tham chiếu thực vẫn có thể thuộc chức năng lành tính.

| Tập | Mẫu | Số anchor | Vai trò |
|---|---|---:|---|
| Train | Gomorrah, PythonStealer2024 | 70 | Cập nhật trọng số |
| Validation | Mercurial | 42 | Đo sau train, không chỉnh tham số theo kết quả |
| Test | AgentTesla | 5 | Khác mẫu train; chỉ có một nhóm truy vấn `send` |

Không có hash mẫu trùng giữa ba tập. Tuy nhiên cả bốn mẫu đều từng được dùng phát triển dự án: đây **không phải benchmark malware chưa nhìn thấy**. Test chỉ năm anchor, không đủ suy rộng chất lượng. Luna không có candidate khớp danh sách truy vấn tại thời điểm thu dữ liệu; không tự thêm record giả.

## Cấu hình và bằng chứng chạy

Giảng viên có thể mở GitHub Actions và chọn bước **Train lại bộ xếp hạng từ dữ liệu đã chốt**. Mỗi lần chạy workflow thực hiện đủ 300 cập nhật trên cả Windows và Ubuntu, từ 70 điểm train trong bộ 117 điểm. Lệnh để tái lập trên máy thành viên là `python training/verify_ranker_reproduction.py --portable`. Nhật ký in cả mức sai khác lớn nhất của loss và tham số. Chế độ mặc định kiểm chính xác từng byte tệp loss và cấu hình. Chế độ đa nền tảng dùng cùng cấu hình, đòi kết quả phân loại và xếp hạng trùng nhau, cho phép sai khác số học tối đa 10⁻¹² với đường loss, trọng số và bias.

Tệp tìm mã trong VM đã có thêm hàm điều hướng trang sau lần train đầu. Bản nguồn lưu theo hash của lần train và bản hiện tại có cùng định nghĩa 13 đặc trưng. Phép tái lập train đọc lại vector đã khóa. Việc trích lại các vector từ mẫu là một thí nghiệm riêng. [Mã nguồn ở thời điểm tạo mô hình](corpus/feature-source-v1.txt) · [Chương trình tái lập](verify_ranker_reproduction.py).

| Lần tái lập trên GitHub Actions | Số bước cập nhật | Chênh loss lớn nhất | Chênh trọng số hoặc bias lớn nhất | Kết quả phân loại và xếp hạng |
|---|---:|---:|---:|---|
| Windows, Python 3.11.9 | 300 | 0 | 0 | Trùng |
| Ubuntu, Python 3.11.18 | 300 | 1,67 × 10⁻¹⁶ | 2,22 × 10⁻¹⁶ | Trùng |

Hai job chạy từ cùng commit. Trong mỗi job, mở bước train để xem hồ sơ kiểm và bước tính điểm để kiểm lại bảng bốn mẫu. [Nhật ký thực nghiệm trên Windows và Ubuntu](https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer/actions/runs/46092717873).

Run [20261127T153436999877Z](experiments/20261127T153436999877Z/receipt.json): CPU, Python 3.11.9, 300 bước full-batch gradient descent, learning rate 0,3, L2 0,01, khởi tạo zero, threshold 0,5. [Loss từng bước](experiments/20261127T153436999877Z/loss.json), [config](experiments/20261127T153436999877Z/config.json), [checkpoint](experiments/20261127T153436999877Z/model.json).

Thời gian ghi nhận 0,0896 giây vì đây là mô hình rất nhỏ; không dùng GPU và không có epoch/loss giả của Qwen. Dataset SHA256 `688a894a07060601925c7d9571d6f2672b372f22d811889400fda76349149905`. Checkpoint SHA256 `030347e4b6d2662df8d68a5424918b835115d2738eb35e1ebb9575216a3d09fd`.

| Phép đo | Train | Validation | Test rất nhỏ |
|---|---:|---:|---:|
| Accuracy nhãn cấu trúc | 97,14% (68/70) | 92,86% (39/42) | 100% (5/5) |
| Hit@1 thứ tự xuất hiện | 41,18% (7/17 nhóm) | 91,67% (11/12) | 0% (0/1) |
| Hit@1 xếp hạng đã train | 70,59% (12/17 nhóm) | 100% (12/12) | 100% (1/1) |

Hit@1 tính trong **tập candidate đã lấy mẫu**, có cả nhóm không có positive. Không phải đánh giá toàn bộ output và không phải Precision/Recall/F1 hành vi/IOC theo slide. Không dùng các số này để đóng gate ANALYSIS/TRUST.

## Tái lập từ Git

```powershell
.\.venv\Scripts\python.exe training/train_ranker.py
```

Lệnh này dùng corpus numeric đã commit, ghi một thư mục experiment mới, không thay model đang dùng. Muốn triển khai kết quả vào retriever:

```powershell
.\.venv\Scripts\python.exe training/train_ranker.py --deploy
.\.venv\Scripts\python.exe scripts/sync_vm.py
.\.venv\Scripts\python.exe scripts/verify_lab.py
```

Trọng số/bias tái lập trong sai số tuyệt đối 1e-12 giữa Windows CRT và Linux libm; timestamp run mới và hash file checkpoint có thể khác vì metadata/bit float cuối. Test phần mềm kiểm tái lập trọng số, loss giảm và việc đảo nhãn validation/test không ảnh hưởng trọng số. Không chạy sync giữa một batch inference.

Thu lại dữ liệu gốc cần VM và output tương ứng. `scripts/collect_retrieval_candidates.py` chỉ xuất đặc trưng có giới hạn. `build_ranker_dataset.py` khóa hash lần thu đã review; không tái dùng nhãn khi dữ liệu thay đổi. Cần bổ sung annotation độc lập của người phân tích, thêm sample/family và test thật chưa dùng phát triển trước khi tuyên bố mô hình tổng quát tốt.

## Tác động tới agent

`search_evidence` dùng checkpoint thật, trả lại anchor, score và hash model. Context luôn giữ anchor dù bị giới hạn dung lượng, và các dòng vẫn có số trong output gốc. Nhật ký run ghi cả hash JSON checkpoint cùng source. Báo cáo cuối vẫn phải kiểm trích dẫn và ngữ nghĩa riêng.

Lượt Gomorrah `20261127T153601_a3240ca6` đã sử dụng retriever mới nhưng vẫn kết luận inconclusive và có claim sai. Đây là bằng chứng cải thiện ranking chưa đủ sửa chất lượng suy luận; không giấu kết quả âm hoặc gọi train này là hoàn thành đồ án.

## So sánh trong vòng ReAct trên AgentTesla

Để tái lập quá trình học trên máy nhóm, chạy `python training/verify_ranker_reproduction.py` từ thư mục gốc sau khi kích hoạt môi trường Python. Lệnh chạy lại 300 bước trên corpus đã khóa và đối chiếu từng trường của mô hình, cấu hình, đường loss cùng chỉ số đánh giá. Lượt kiểm ngày 28/11 cho cùng trọng số, bias, loss và chỉ số. Mỗi lần train sinh một run ID riêng nên hai tệp checkpoint có SHA-256 khác nhau. [Kết quả đối chiếu](ranker-reproduction.json).

Hai lượt dùng cùng mẫu, cùng phiên bản bộ điều phối, model Qwen3 8B và seed 42. Ở nhánh đối chứng, VM trả kết quả theo thứ tự dòng trong mã. Ở nhánh dùng ranker, mỗi lần tìm mã ghi lại hash checkpoint đã nạp. Hai nhánh cùng được phép chuyển sang trang mới khi tìm rỗng. Trình đối chiếu kiểm các điều kiện này từ nhật ký thật. [Biên bản hai lượt](../deliverables/real-demo-evidence/agenttesla-ranker-ablation.json).

| Phép đo | Theo thứ tự dòng | Dùng ranker đã train |
|---|---:|---:|
| Truy vấn có kết quả / tổng | 9/14 | 8/14 |
| Câu được giữ / câu thô | 12/13 | 12/15 |
| Câu được giữ có đủ căn cứ | 9/12 | 10/12 |
| Mục đúng / 7 mục đã chốt | 2/7 | 2/7 |
| F1 trong phạm vi 7 mục sau lọc | 33,33% | 36,36% |
| Thời gian | 465,8 giây | 575,1 giây |
| Verdict | inconclusive | inconclusive |

Cả hai lượt tìm thấy thao tác nạp assembly và gọi phương thức qua phản chiếu. Cả hai bỏ sót kênh SMTP được tác giả bộ mẫu ghi nhận. Chênh lệch F1 đến từ số nhận định sai hoặc thiếu căn cứ. Độ phủ bằng nhau và nhánh dùng ranker tốn thêm khoảng 109 giây. Một cặp trên một mẫu phát triển chưa đủ để kết luận ranker cải thiện hiệu quả trên các họ khác. [Bảng 13 câu của đối chứng](../deliverables/real-demo-evidence/20261128T002140_6b8034a7/review.md) · [Bảng 15 câu của nhánh đã train](../deliverables/real-demo-evidence/20261128T001144_4a8326ca/review.md).

Chạy trên máy đã dựng lab, trong PowerShell ở thư mục dự án. Sau hai lượt, lấy chính hai run ID do máy in ra để dùng với `scripts/compare_ranker_runs.py --before ID_DOI_CHUNG --after ID_RANKER --output evidence/local/so-sanh-ranker.json`.

```powershell
.\scripts\Run-Demo.ps1 -Sample public_agenttesla.bin -Profile guided-8b -OccurrenceOrder
.\scripts\Run-Demo.ps1 -Sample public_agenttesla.bin -Profile guided-8b
```

## Nhãn từ giao diện điều tra

Mục **Gán nhãn** cho phép người phân tích đối chiếu từng vị trí với nguồn của một lượt thật. Lệnh `python -m training.train_web_ranker` kiểm mã nguồn, phiên bản đặc trưng và phân chia theo mẫu trước khi tạo trọng số ứng viên. Nhóm cần bổ sung nhãn do người đọc mã xác nhận để đo tác động của phản hồi mới lên báo cáo. [Quy trình nhập nhãn và train lại](../docs/WEB_DIEU_TRA.md#huấn-luyện-từ-nhận-xét)
