# Nguồn yêu cầu của giảng viên và đề xuất gốc

Các tệp gốc được giữ nguyên byte và tên; bảng dưới là chỉ mục để giảng viên/nhóm đối chiếu.

- [File đề xuất gốc](reference/13-Đồ-án-AI-Agent-phân-tích-mã-độc-Stealer-.NET-Python-ReAct-SLM-cục-bộ-.md)
- [Thuyết minh hiện tại](THUYET_MINH_DU_AN.md)
- [Mục tiêu và gate](PROJECT_GOAL.md)
- [Backlog nhóm](CONG_VIEC_CON_LAI.md)

| Ảnh | Nội dung đọc từ slide |
|---|---|
| [Ảnh 1](reference/1-Ảnh-1.jpg) | Chỉ số chất lượng agent (bản chụp toàn cảnh) |
| [Ảnh 2](reference/2-Ảnh-2.jpg) | Precision/Recall/F1, verdict, bịa, dẫn chứng, stability, YARA, injection, hiệu quả |
| [Ảnh 3](reference/3-Ảnh-3.jpg) | Chọn SLM/LLM theo RAM/VRAM; gợi ý model |
| [Ảnh 4](reference/4-Ảnh-4.jpg) | Nội dung 9 buổi |
| [Ảnh 5](reference/5-Ảnh-5.jpg) | Chi tiết hướng 7–12 |
| [Ảnh 6](reference/6-Ảnh-6.jpg) | Yêu cầu đồ án: ReAct, tool thật, VM, output/log và sản phẩm nộp |
| [Ảnh 7](reference/7-Ảnh-7.jpg) | Chi tiết hướng 1–6, gồm I/J và SLM 7B |
| [Ảnh 8](reference/8-Ảnh-8.jpg) | Danh sách hướng đề tài |
| [Ảnh 9](reference/9-Ảnh-9.jpg) | Thang điểm 3+2+2+1+2 |
| [Ảnh 10](reference/10-Ảnh-10.jpg) | Mốc buổi 2/4/6/8/báo cáo và quy định |
| [Ảnh 11](reference/11-Ảnh-11.jpg) | Nội dung 9 buổi (bản toàn cảnh) |
| [Ảnh 12](reference/12-Ảnh-12.jpg) | Quy trình AI: dữ liệu, đặc trưng, train, đánh giá, triển khai, giám sát |

## Các chỉ tiêu cần đối chiếu

- P>=0,8; R>=0,7; F1>=0,75. Rubric xuất sắc: F1>=0,8 và verdict đúng hết.
- Bịa <=5%; dẫn chứng >=90%; ổn định 3 lần>=80%.
- YARA TPR>=90%, FPR=0; prompt-injection success=0%, bộ thử>=10 file cho mức xuất sắc.
- Kỹ thuật agent mức xuất sắc: >=4 tool thật. Buổi 4 chỉ yêu cầu >=2 tool.
- Trọng số: chất lượng3,0; tin cậy2,0; kỹ thuật2,0; an toàn/đạo đức1,0; báo cáo/demo/vấn đáp2,0.
- I=.exe .NET 5.632 byte; J=.exe PyInstaller khoảng 8 MB; ILSpy/dnSpyEx và pyinstxtractor+pycdc; SLM 7B; output kênh gửi/token/webhook.
- Không gửi binary mẫu lên LLM cloud, không cho agent chạy lệnh ngoài VM cô lập, không nộp thiếu nhật ký thật.

Ảnh 12 nhắc bước huấn luyện trong quy trình AI nói chung. Ảnh 6/10 cho phép SLM local hoặc LLM API; từ ảnh đó không suy ra đã có fine-tuning trong dự án. Yêu cầu bổ sung về train được nhóm xác nhận qua trao đổi ngày 27/11/2026 nhưng cách train chưa được thầy làm rõ. Xem training/DECISION_LOG.md.

Các hiệu chỉnh thiết kế so với đề xuất (Ubuntu thay FLARE-VM, pefile bổ sung DIE, giới hạn managed static-only của FLOSS, mẫu public và pycdas fallback) nằm trong THUYET_MINH_DU_AN.md. Đề xuất gốc trong reference được giữ nguyên.
