# Trách nhiệm kỹ thuật theo module

Tài liệu này mô tả các phần của sản phẩm để thành viên dễ tiếp nhận. Không yêu cầu tên, MSSV, bìa báo cáo hoặc xác nhận phân công cá nhân. Theo chỉ đạo mới nhất, các mục hành chính không chặn công việc kỹ thuật.

| Phần | Mã nguồn chính | Cần hiểu và kiểm chứng |
|---|---|---|
| Môi trường và công cụ | scripts/, vm_tools/ | VM host-only, cài offline/hash, phiên bản backend, giới hạn parser, quyền file |
| .NET và Python | vm_tools/service.py, python_tools.py, native_tools.py | ILSpy; PyInstaller/pycdc/pycdas; DIE/FLOSS; lỗi phục hồi source |
| Agent và mô hình | stealer_agent/ | SLM chọn action, schema, ngân sách context, log request, guard, citation, reviewer |
| Dữ liệu và đánh giá | eval/, training/, config/public-samples.json | Nhãn độc lập, split, P/R/F1, stability, YARA, injection, huấn luyện có log thật |
| Tái lập | docs/TEAM_SETUP.md, scripts/Run-Demo.ps1 | Clone, tải model/archive có hash, dựng VM, chạy và đọc báo cáo |

Công việc cụ thể và tiêu chí đóng nằm trong [CONG_VIEC_CON_LAI.md](CONG_VIEC_CON_LAI.md). Không tự gán người đã review hoặc ký duyệt nhãn. Nếu nhóm muốn dùng tài liệu này để phân công trước lớp thì tự thêm tên ở bản riêng.

## Tự kiểm khả năng giải thích sản phẩm

- Chỉ ra một action của SLM và observation tương ứng từ backend thật.
- Phân biệt hash chain với xác nhận đúng nội dung; phân biệt citation với chứng cứ hành vi.
- Giải thích tại sao Ollama ở host nhưng file mẫu và parser ở VM.
- Giải thích lỗi pycdc và giới hạn của bytecode fallback.
- Chỉ ra dữ liệu huấn luyện, checkpoint và phép so sánh nếu đã train; trạng thái chưa train phải được nói đúng.
