# Model card của baseline buổi 4

Đây là card lịch sử của SLM baseline, không ghi đè bằng số liệu model phụ trợ. Phần bổ sung sau mốc 4: [ranker đã train](RANKER_EXPERIMENT.md), [so sánh Qwen3 8B bị dừng vì thiếu RAM](../docs/MODEL_COMPARISON.md), cấu hình hiện tại ở config/host.example.json. Qwen7B vẫn chưa được fine-tune.

| Trường | Giá trị |
|---|---|
| Upstream | Qwen/Qwen2.5-Coder-7B-Instruct |
| Giấy phép | Apache-2.0; bản license ở docs/licenses |
| Model demo | qwen2.5-coder:7b, GGUF Q4_K_M qua Ollama |
| Tham số quan sát | 7.615.616.512 |
| Digest Ollama | dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364 |
| SHA256 weight blob | 60e05f2100071479f596b964f89f510f057ce397ea22f2833a0cfe029bfc2463 |
| Weight blob bytes | 4.683.074.048 |
| Suy luận | temperature0,seed42,num_ctx 4096,num_predict 900,max_steps 12 |
| Runtime quan sát | Ollama0.40.17; loopback11435 |
| Nhóm tự pretrained từ đầu? | Không |
| Fine-tuning/adapter của nhóm? | Chưa |
| Corpus/loss/epoch của nhóm | Chưa có |

Nguồn: [Qwen model card](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct). Pretraining/instruction tuning upstream thuộc nhà phát hành model; nhóm không nhận là huấn luyện của mình. Nhóm xây controller/tools/schema/guard/evidence/evaluation và thực nghiệm suy luận.

Chọn Coder 7B dựa vào dòng model code, yêu cầu tối thiểu7B và việc đã chạy trên máy12GBRAM/RTX3050 6GB. Chưa có thí nghiệm để tuyên bố nó tốt nhất. Model cũ Qwen2.5 1.5B trên D thấp hơn yêu cầu hướng 6 và được giữ nguyên.

Giới hạn: báo cáo public còn inconclusive; citation có thể đúng vị trí nhưng không hỗ trợ ngữ nghĩa; reviewer có phản ví dụ; pycdc chưa xử lý đầy đủ Python 3.11. Context nhỏ giới hạn chứng cứ nhìn thấy. Chưa có F1 độc lập hoặc so sánh sau train.

Nếu train về sau: tạo model card mới với base HF revision, split hash, adapter hash, config/run/log/evaluation và tag Ollama khác; không sửa baseline card để làm như adapter đã tồn tại ở buổi 4.
