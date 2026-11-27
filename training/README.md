# Hồ sơ huấn luyện: trạng thái thực và cách tái lập

**Hiện tại: đã train một mô hình ML phụ trợ xếp hạng chứng cứ; CHƯA fine-tune SLM.** [Thực nghiệm ranker](RANKER_EXPERIMENT.md) có corpus numeric, split theo mẫu, optimizer, loss 300 bước, checkpoint và số đo thật. Qwen vẫn dùng trọng số upstream. Không có adapter/epoch/loss SLM của nhóm. [Trạng thái máy đọc được](status.json).

Ngày 27/11/2026, nhóm bổ sung yêu cầu “thầy xem Git phải thấy train như thế nào”, nhưng chưa rõ fine-tune chính SLM hay ML phụ trợ. [DECISION_LOG](DECISION_LOG.md) ghi phạm vi chưa xác nhận. Ranker được xây để xử lý lỗi truy xuất thật; không tự coi nó thay yêu cầu fine-tune SLM. Các mục QLoRA bên dưới vẫn là **quy trình và code ứng viên**.

## Giảng viên nên xem gì?

1. [MODEL_CARD](MODEL_CARD.md): nguồn base model, cấu hình suy luận đã dùng, trách nhiệm upstream/nhóm.
2. [status.json](status.json): có/chưa train, số train run thực, trạng thái dataset và checkpoint.
3. [configs/qlora.example.json](configs/qlora.example.json): hyperparameter dự kiến, không gọi là tham số tối ưu.
4. [DATASET_PROTOCOL](DATASET_PROTOCOL.md): nguồn nhãn, review, chống rò rỉ, cách tách tập.
5. [validate_dataset.py](validate_dataset.py): kiểm dữ liệu trước khi tải model.
6. [train_lora.py](train_lora.py): script ứng viên cập nhật adapter, chỉ chạy khi có dữ liệu được duyệt và lệnh execute.
7. [EXPERIMENT_CHECKLIST](EXPERIMENT_CHECKLIST.md): các tệp bắt buộc lưu từ một run thực.

## Cần phân biệt bốn việc

| Hoạt động | Có cập nhật trọng số bởi nhóm? | Hiện trạng |
|---|---|---|
| Tải Qwen/GGUF, chạy Ollama | Không | Đã làm |
| Viết prompt, schema, controller, guard | Không | Đã làm |
| Đặt temperature/seed/context hoặc dùng Q4 | Không phải fine-tuning | Đã cấu hình suy luận; dùng weight lượng tử upstream |
| Train ranker logistic regression | Có | Đã train CPU, có loss/checkpoint; nhãn cấu trúc tự động, chưa được người thật duyệt |
| SFT/LoRA/QLoRA của SLM | Có nếu chạy optimizer cho adapter | Chưa làm |

Không tự lấy nhật ký inference, unit-test fixtures hoặc ví dụ trong file đề xuất làm training evidence.

## Hướng dự kiến nếu GV yêu cầu fine-tune SLM

Mục tiêu hẹp: học trả JSON action hợp lệ, chọn công cụ từ observation, trích citation đúng và biết trả inconclusive. Không huấn luyện mô hình viết/chạy stealer. Nhãn phải do người phân tích kiểm chứng; raw output hiện có có claim sai nên không được tự biến thành đáp án.

Chọn LoRA trên base Qwen2.5 Coder 7B Instruct; có thể dùng lượng tử 4 bit NF4 khi train (QLoRA) để giảm bộ nhớ. GGUF Q4_K_M của Ollama **không phải** thư mục Hugging Face checkpoint dùng trực tiếp cho script này. Cần bản base Safetensors và tokenizer đúng revision, được lưu cục bộ và ghi hash. [PEFT quantization](https://huggingface.co/docs/peft/v0.17.0/en/developer_guides/quantization).

VRAM 6 GB đã đủ chạy inference trong thử nghiệm nhưng không chứng minh đủ train 7B. Cấu hình dự kiến dùng sequence 512, microbatch 1, accumulation 16, rank 8, lr 1e-4, 1 epoch; đây là điểm xuất phát để đo OOM/loss, không là cấu hình đã kiểm GPU hoặc được tối ưu. Chuẩn bị GPU lab có dư bộ nhớ; chỉ quyết định sau dry-run đo thực. Không tự đổi model cuối xuống dưới 7B để bỏ qua yêu cầu hướng 6.

## Quy trình chạy dự kiến

**Bước 1 — Dữ liệu.** Người phụ trách tạo private/training-data/train.jsonl, validation.jsonl, test.jsonl theo DATASET_PROTOCOL; hai người review. Hiện thư mục này chưa có corpus đã duyệt. Không có file mẫu train giả được dùng thay.

```powershell
.\.venv\Scripts\python.exe training/validate_dataset.py --data-dir private/training-data
```

Thiếu file, trùng family/sample/prompt qua tập, nhãn chưa duyệt hoặc có token thật sẽ làm dừng. Kiểm cơ học không thay review nội dung.

**Bước 2 — Môi trường riêng.** Dùng Python 3.11 trong môi trường GPU huấn luyện riêng; không thay .venv của demo. requirements-candidate.txt ghim các bản ứng viên đã có trên PyPI, nhưng tổ hợp GPU/CUDA chưa được kiểm. Lưu pip freeze, CUDA/driver/GPU và lỗi cài đặt thật. Không cài/chạy train trong lượt bàn giao buổi 4 hiện tại.

**Bước 3 — Base model.** Tải từ nguồn Qwen vào thư mục local riêng trước khi chạy; ghi revision từ upstream và hash file. Script dùng local_files_only=True, không tự tải model hoặc upload dữ liệu. Không dùng trust_remote_code.

**Bước 4 — Chạy có chủ đích.**

```powershell
python training/train_lora.py --config training/configs/qlora.example.json --validate-only
python training/train_lora.py --config training/configs/qlora.example.json --execute
```

Lệnh thứ nhất chỉ validate, không train và không tải GPU. Lệnh thứ hai yêu cầu base HF đã có, corpus hợp lệ và CUDA; sinh thư mục run mới dưới private/training-runs. Không ghi đè run cũ. Script lưu config/data hashes/environment, loss history, trainer state, adapter/tokenizer, SHA256 và lỗi. Code ứng viên chưa được nghiệm thu GPU.

**Bước 5 — Đánh giá.** So baseline với adapter trên test khóa trước, chạy agent cùng tools/schema/seeds; chấm claim độc lập theo tiêu chí GV. Eval loss là phép đo tối ưu hóa, không phải F1 phân tích mã độc. Không được tối ưu trên test rồi báo đó là holdout.

**Bước 6 — Triển khai.** Merge/export adapter trên base phù hợp, convert/quantize bằng tool tương thích rồi import thành tag Ollama mới. Không ghi đè qwen2.5-coder:7b baseline. Việc export/convert/tag mới là backlog chưa triển khai, phải kiểm GGUF digest và parity trước khi dùng. [Ollama import](https://docs.ollama.com/import).

## Git cần chứa gì sau khi train thật?

Commit code/config/data manifest/split policy và bản dữ liệu đặc trưng đã duyệt để chia sẻ; không commit binary mẫu/token/raw credentials. Thêm thư mục experiments/<run-id>/ gồm receipt, log loss thật, pip freeze, dataset hashes, base revision, checkpoint hash, bài so sánh baseline/adapter và phiếu chấm. Trọng số adapter/checkpoint dung lượng lớn đặt Release có hash.

Thư mục experiments hiện có một run ranker thật; không được diễn giải nó là run SLM. Không điền số epoch/accuracy/loss SLM giả. Phần TRAIN của rubric vẫn cần xác định loại train được chấp nhận và đánh giá độc lập; tiến độ hiện tại là toàn đồ án, không dừng ở buổi 4.
