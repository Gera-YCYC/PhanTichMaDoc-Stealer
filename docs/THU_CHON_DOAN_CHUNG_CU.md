# Qwen có tìm thêm được hành vi khi đọc nhiều chứng cứ hơn?

Trên ba mẫu phát triển, đọc thêm hai đoạn mỗi mẫu giúp bốn mục tham chiếu lần đầu có đủ dòng trong cùng một yêu cầu. Qwen tạo thêm mười câu. Năm câu được giữ đều nói về các hành vi hoặc chỉ báo đã có trong báo cáo gốc. Vì vậy nhóm giữ cấu hình chọn đoạn hiện hành cho demo. Mở **Đánh giá**, chọn mẫu và mở **Qwen đọc thêm hai đoạn chứng cứ** để xem từng câu.

## Cách đo

Nhóm còn thử thu hẹp từng câu bị loại trên chính phần mã đã dẫn. Thí nghiệm đó đo độ đúng của câu hẹp và quyết định của bộ duyệt. [Kết quả 13 câu và biên bản web](DOC_LAI_NHAN_DINH.md)

Nhóm dùng lại quan sát mà VM trả cho ba lượt web đã chấm. Bộ chọn chỉ đọc các dòng đã quan sát, kết quả tìm và thao tác do parser xác định. Sau khi chọn xong mới đối chiếu với 97 mục đã chốt. Một mục được tính vào bảng dưới khi tất cả dòng tham chiếu của nó xuất hiện cùng nhau trong ít nhất một đoạn gửi ở bước tạo câu. Ở bước tái lập, chương trình so cả số dòng lẫn nội dung đánh số với yêu cầu Qwen thực sự nhận. Ba nguyên mẫu giữ cùng digest mô hình. [Biên bản ba mẫu](CHAM_BA_MAU_WEB.md) · [Các vùng dòng đã chọn](../deliverables/real-demo-evidence/web-card-coverage.json)

| Mục có đủ dòng trong một đoạn | Python · 36 mục | Gomorrah · 40 | Mercurial · 21 | Tổng trên 97 |
|---|---:|---:|---:|---:|
| Đoạn gốc | 24 | 13 | 8 | 45 |
| Đổi đoạn để ưu tiên thao tác, vị trí và dòng mới | 18 | 12 | 8 | 38 |
| Mở rộng quanh đoạn gốc | 24 | 13 | 8 | 45 |
| Giữ đoạn gốc và đọc thêm hai đoạn | 24 | 16 | 9 | 49 |

Ở phương án đổi đoạn, mỗi vị trí dùng tối đa số byte UTF-8 của phần mã đánh số ở vị trí gốc. Riêng Gomorrah thu thêm năm mục và mất sáu mục. Phương án mở rộng giữ dòng cũ và cho phép thêm tối đa 20% byte của phần mã mỗi yêu cầu. Hai phép đo này chỉ xét phần mã hiện diện. Phương án đọc thêm hai đoạn đã chạy suy luận thật bằng Qwen3 8B trên Windows, từ các quan sát VM có sẵn. Các lượt đầu–cuối để chấm chất lượng vẫn là ba lượt gốc.

## Mười câu được chấm như thế nào?

| Mẫu | Qwen tạo → giữ | Mục đúng mới sau duyệt | Lượt gọi model | Token vào / ra | Giây |
|---|---:|---:|---:|---:|---:|
| PythonStealer | 5 → 5 | 0 | 8 | 12.507 / 588 | 78,51 |
| Gomorrah | 4 → 0 | 0 | 6 | 7.774 / 515 | 53,28 |
| Mercurial | 1 → 0 | 0 | 3 | 3.353 / 159 | 22,56 |

Sáu lượt tạo, mười lượt duyệt và một lượt tổng hợp riêng trên Python dùng 23.634 token vào, 1.262 token ra và gần 154,36 giây. Việc chấm giữ nguyên cả câu bị loại. Cột mục đúng mới chỉ đếm các mục tham chiếu có trong câu đúng được giữ, sau khi loại mục mà báo cáo gốc đã có. Phần đúng trong một câu có thêm khẳng định thiếu chứng cứ được ghi riêng để giải thích. [Mười quyết định và tọa độ](../deliverables/real-demo-evidence/web-card-supplements.json)

- **PythonStealer.** Bằng chứng cho cấu hình SMTP, xác thực và tạo phần đính kèm đã xuất hiện trong báo cáo gốc. Câu lặp có thể đúng mà vẫn không làm tăng recall.
- **Gomorrah.** Dòng 1067–1072 cho thấy tạo bản ghi tài khoản với kết quả một hàm phụ. Câu của Qwen còn gọi kết quả đó là mật khẩu đã giải mã. Bằng chứng hiện có chỉ cho phép giữ nhận định hẹp hơn về lời gọi và phép gán.
- **Mercurial.** Dòng 375, 380–385 và 391 hỗ trợ nhận định về một lời gọi giải mã gốc với cấu hình AES-GCM. Qwen loại câu này. Trên cùng mẫu, câu C17 ở báo cáo gốc lại được Qwen giữ dù nhầm tham số hàm bao với tham số thật của API mở provider.

## Tài liệu API có sửa được lỗi tự duyệt?

Nhóm chạy lại tất cả yêu cầu duyệt có chứa `BCrypt` trong hai nhật ký Mercurial nói trên. Mỗi câu được duyệt hai lần với cùng nội dung chứng cứ, schema, digest Qwen, seed 42 và temperature 0. Nhánh thử thêm ghi chú về đối số của API vào system prompt. Thứ tự hai nhánh đảo giữa các câu liền kề. Chỉ bộ chấm biết nhãn. Tài liệu tham chiếu mô tả quy ước API và cách truyền thông tin xác thực qua cấu trúc tham số. [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt) · [Cấu trúc cho chế độ xác thực](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info) · [Mở provider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider) · [Đặt thuộc tính](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty)

| Câu | Đối chiếu nguồn | Duyệt gốc chạy lại | Thêm tài liệu |
|---|---|---|---|
| C17 gốc, truyền chế độ vào API mở provider | Sai | Giữ | Giữ |
| C18 gốc, đặt thuộc tính trên đối tượng | Đúng | Giữ | Giữ |
| C1 bổ sung, lời gọi giải mã gốc | Đúng | Loại | Loại |

Cả hai nhánh quyết định đúng 1/3 câu và tái hiện cùng hai lỗi. Ba câu thuộc một mẫu phát triển, được chọn sau khi phát hiện lỗi. Nhóm giữ biến thể này trong thư mục thí nghiệm. Hướng cần thử tiếp là kiểm đối số nào đi vào lời gọi nào và tách câu có nhiều mệnh đề trước khi chấm. Phải đo mức báo nhầm, bỏ sót trên mẫu khác trước khi đổi bộ duyệt trong agent. [Biên bản sáu lần suy luận](../deliverables/real-demo-evidence/web-cng-review.json)

## Kiểm tra từ Git hoặc từ máy lab

Từ thư mục dự án, dùng môi trường Python đã cài trong hướng dẫn của nhóm.

```powershell
.\.venv\Scripts\python.exe -m eval.supplement_review
.\.venv\Scripts\python.exe -m eval.web_report_quality
```

Trên máy lab có nhật ký riêng của các lượt đã ghi, ba lệnh sau đối chiếu hash, nội dung yêu cầu, tọa độ nguồn và kết quả duyệt. Có thể chạy khi Ollama và VM đã tắt.

```powershell
.\.venv\Scripts\python.exe -m eval.card_coverage
.\.venv\Scripts\python.exe -m eval.supplement_review --replay
.\.venv\Scripts\python.exe -m eval.cng_review_trial --verify
```

Để tạo một lần suy luận bổ sung mới từ các quan sát đã thu, khởi động Ollama cục bộ và dùng mã lượt ở bảng ba mẫu. Ví dụ dưới dùng Mercurial. Mỗi lần chạy ghi nhật ký riêng dưới `private/`; biên bản đã chấm trong Git giữ nguyên.

```powershell
.\scripts\Start-LocalModel.ps1 -PromptCacheMiB 0
try {
    .\.venv\Scripts\python.exe scripts/replay_card_report.py --run 20261128T031606_ca91de35 --config config/host.investigation.example.json --method supplement --cards 2
    .\.venv\Scripts\python.exe -m eval.cng_review_trial
} finally {
    .\scripts\Stop-LocalModel.ps1
}
```
