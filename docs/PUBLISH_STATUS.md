# Trạng thái phát hành đã kiểm chứng

Repo chính từ cập nhật quyền nhóm: [Gera-YCYC/PhanTichMaDoc-Stealer](https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer), public. Source hiện tại và tài liệu nằm tại root. Bản gốc ở commit `9362d1c0c8455bb15ff089c4b7c0bbc5b0f356f4` được giữ nguyên 27 file dưới `legacy/initial-version/`, có manifest SHA256; lịch sử của tác giả ban đầu được giữ.

Tài nguyên dùng [Release tai-nguyen-lab-20261127 của repo nhóm](https://github.com/Gera-YCYC/PhanTichMaDoc-Stealer/releases/tag/tai-nguyen-lab-20261127): cùng 10 asset/4.723.303.595 byte và hash đã khóa, gồm 3 phần model, 5 archive nghiên cứu mã hóa và 2 manifest. Đây là chuyển nơi phân phối, không phải tuyên bố hoàn tất các chỉ tiêu chất lượng đồ án. Script chỉ công bố Release sau khi kích thước/digest của toàn bộ asset khớp.

Các mục bên dưới là **lịch sử kho tạm**, giữ liên kết cũ để truy vết các lần kiểm chứng; không phải repo nhận push tiếp theo.

**Release đã công bố:** [buoi4-real-demo-20261127](https://github.com/duongthanhmong/PhanTichMaDoc_DoAn/releases/tag/buoi4-real-demo-20261127).

- Release gắn commit `13e6d62cf7009db3ce909c5d6a9f0cdbc6f1fdc6`. Các commit tài liệu/receipt tiếp theo nằm trên main; không đổi tag hoặc sửa lịch sử.
- Đã upload đủ **10 asset**, tổng **4.723.303.595 byte**: 3 phần model, 5 archive mẫu public mã hóa và 2 manifest.
- Dung lượng, trạng thái uploaded và SHA256 do GitHub trả về khớp toàn bộ `config/release-assets.lock.json`.
- Đã tải không đăng nhập cả 7 tệp nhỏ và kiểm SHA256. Ba phần model đã thử HTTP range 1.024 byte/part, khớp phần đầu file local. Toàn bộ SHA256 các part được kiểm qua digest phía GitHub; không tuyên bố đã tải lại toàn bộ 4,68 GB qua mạng.
- Remote Git tree/blob của commit Release khớp toàn bộ 151 tệp source local lúc công bố.
- GitHub Actions của commit Release: [49 kiểm thử đạt trên Ubuntu](https://github.com/duongthanhmong/PhanTichMaDoc_DoAn/actions/runs/46013999142). Không chạy model, VM hoặc mã độc trong CI.
- Author/committer của các commit mới là tài khoản duongthanhmong; không có AI co-author, không cấp collaborator cho công cụ. Lịch sử initial commit của repo được giữ.

[Biên bản kiểm công bố](../deliverables/real-demo-evidence/publication-verification.json) ghi thời điểm, commit và từng asset. Bản này chỉ có metadata đã rà soát; không có khóa hoặc mẫu giải mã.

## Giới hạn bằng chứng

Model đã được phục hồi 8 member đúng hash; 5 mẫu đã được giải mã/kiểm hash trong VM; hai demo thật đã chạy lại trên lab gốc và một VM mới cùng host. Các receipt nằm ở deliverables/real-demo-evidence. Không thực thi mẫu; chưa kiểm trên máy vật lý thứ hai.

Receipt Release ghi demo/CI tại mốc buổi4. Đợt phát triển tiếp đã được người dùng cho phép bật runtime, tích hợp DIE/FLOSS và chạy thêm mẫu thật; xem STATUS và native-tools-and-navigation-runs.json. Không dùng CI hoặc kiểm tải Release thay demo/đánh giá chất lượng.

Commit main `441148ed1dfb9fa561259b91f9bfa20d881a48e2` đã push và kiểm 175 Git blob khớp local. [CI 79 tests đạt trên Ubuntu](https://github.com/duongthanhmong/PhanTichMaDoc_DoAn/actions/runs/46025320160). Release/tag/10 asset vẫn nguyên trạng. Các bổ sung ranker/decoder sau đó có kiểm local riêng và chỉ ghi đã publish khi có commit/CI tương ứng.

Buổi 4 là mốc tích hợp đã qua; các chỉ tiêu nghiệm thu cuối môn còn mở. Đọc STATUS, training/README và CONG_VIEC_CON_LAI.

Khóa cá nhân, seed/VM chứa khóa và raw logs không đưa lên Git/Release. [Receipt tắt runtime cũ](../deliverables/real-demo-evidence/runtime-stopped.json) là lịch sử đợt phát hành đầu, không đại diện trạng thái hiện tại. File model/VM giữ cục bộ. Thành viên clone repo, tải Release và dựng khóa/VM riêng theo [TEAM_SETUP](TEAM_SETUP.md); không cần khóa MalwareBazaar cho bộ archive đã phát hành.
