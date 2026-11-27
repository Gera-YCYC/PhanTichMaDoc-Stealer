# Quyết định tận dụng repo tham khảo

Nguồn: Gera-YCYC/PhanTichMaDoc-Stealer, commit 9362d1c0c8455bb15ff089c4b7c0bbc5b0f356f4; bản đọc nguyên trạng ở `audit/friend-repo`, kiểm tra tại `audit/AUDIT_REPORT.md`.

- Giữ ý tưởng module hóa, ReAct chọn hành động, hash/entropy, nhận diện PE/CLR, AST thu đặc trưng, IOC regex và JSON/Markdown.
- Giữ bộ ca tái hiện lỗi làm yêu cầu regression. Mã mới triển khai với hợp đồng kiểu dữ liệu và nguồn dẫn chứng rõ ràng.
- Không đưa nguyên trạng fallback BENIGN, phép hợp nhất IOC không xác minh, danh sách bị chèn string khi truncate, hay dispatcher chạy trên host vào hệ thống mới.
- Backend thiếu phải unavailable; parser lỗi phải incomplete; YARA không có fallback giả làm YARA; tool đọc theo sample ID, không đường dẫn do mô hình tự chọn.
- Tại thời điểm audit, bản gốc chưa sửa và chưa push. Khi nhóm cấp quyền ghi, toàn bộ 27 file của commit này được giữ nguyên dưới `legacy/initial-version/`, đối chiếu bằng `docs/legacy-source-manifest.json`. Các thực nghiệm cũ không được coi là nghiệm thu dự án mới.
