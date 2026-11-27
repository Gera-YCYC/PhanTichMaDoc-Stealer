# Luật do SLM chọn và VM đã kiểm

Các file `.yar` ở đây là luật phòng thủ xuất từ lần chạy thật, sau khi kiểm nội dung trước công bố. Model chọn ID chuỗi/điều kiện; controller tạo cú pháp, giới hạn kích thước, PE magic và ràng buộc entry PyInstaller nếu có. Không dùng hash mẫu làm luật, không gọi luật tự chọn thủ công là đầu ra model.

Mỗi luật phải đối chiếu đúng hash trong receipt của run. Corpus, từng mẫu khớp/không khớp, tag/digest model và nhật ký công khai ở `deliverables/real-demo-evidence/yara-runs/`. Log công khai là metadata đã lọc; nguyên request, response và byte-source evidence giữ trong `runs/` cục bộ.

Luật tên entry PyInstaller là chỉ dấu bản build đã quan sát, dễ mất tác dụng khi đổi tên/đóng gói lại. Không dùng kết quả của corpus nhỏ để kết luận độ nhạy cho toàn bộ họ stealer hoặc thay thế phân tích hành vi. Xem `docs/YARA_REAL_CORPUS.md` và kết quả âm ban đầu với yt-dlp.
