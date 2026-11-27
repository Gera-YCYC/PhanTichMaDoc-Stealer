# Bằng chứng của một run huấn luyện thực

Chưa có run huấn luyện hoàn tất. Không điền log minh họa như số đo thật.

| Artifact | Nội dung |
|---|---|
| run-receipt.json | UTC start/end, command, seed, status/lỗi |
| config.json | Hyperparameter, LoRA targets/rank, quantization, batch/context |
| base-inventory.json | Upstream/revision và SHA256 từng file HF local |
| dataset-validation.json | Hash, số group/sample/record mỗi split, review/leakage |
| environment.json,pip-freeze.txt | Python/OS, thư viện, GPU/CUDA/driver |
| trainer_state.json,loss-history.json | Step/epoch/loss/lr/eval_loss thực |
| adapter/,checkpoint-hashes.json | Adapter/tokenizer thực và digest |
| evaluation/ | Agent reports, adjudication, baseline vs adapter trên test khóa |
| limitations.md | OOM, thiếu dữ liệu, kết quả âm, contamination chưa loại trừ |

Sau train cập nhật status.json bằng run ID/artifact có thật. Run thất bại giữ failed receipt, không tăng completed_training_runs. Loss curve chỉ vẽ từ log thật; loss giảm không đồng nghĩa vượt ngưỡng giảng viên. So baseline/adapter giữ sample/code/tool/config thống nhất và ghi yếu tố được đổi.
