# Thực nghiệm train bộ xếp hạng chứng cứ

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
