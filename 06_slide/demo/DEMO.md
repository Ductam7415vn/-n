# Kịch bản demo trước hội đồng (khoảng 3 phút)

Chạy thử ngày 2026-11-10 trên MacBook Apple Silicon. Thời gian lần đầu (chưa có cache, gồm cả apktool + JADX):
InsecureBankv2 13–19 s, NewPipe 25–45 s. Khi đã có cache: dưới 1 s.

## Chuẩn bị (trước giờ bảo vệ)

1. Cắm ổ SSD BetaSoft, mở Terminal ở thư mục đồ án: `cd "/Volumes/BetaSoft/Desktop/Đồ án"`.
2. Kiểm tra công cụ: `apktool --version && jadx --version && python3 04_code/scripts/apiscan.py --version`.
3. Chạy một lần để có cache: `bash 06_slide/demo/demo.sh --newpipe`. Lúc demo sẽ ra kết quả ngay.
4. Phóng to chữ Terminal (⌘ +) và thu nhỏ các cửa sổ khác.

## Trình tự demo

| Bước | Lệnh / thao tác | Nói gì |
|---|---|---|
| 1 | `bash 06_slide/demo/demo.sh` | "Một lệnh: từ tệp APK tới báo cáo. Công cụ giải nén, dịch ngược, tự xác định mã của ứng dụng rồi chạy 20 luật." |
| 2 | Terminal in tóm tắt: 22 cảnh báo ở ngưỡng ≥ medium | "Đây là ứng dụng ngân hàng cố ý có lỗi; ở ngưỡng khuyến nghị công cụ vẫn bắt đủ 6/6 lỗ hổng tĩnh của đáp án." |
| 3 | Báo cáo HTML tự mở — chỉ vào một cảnh báo high (khoá AES viết cứng, CRY-KEYHARD) | "Mỗi cảnh báo có OWASP, mức nghiêm trọng, độ tin cậy, tệp:dòng và đoạn mã bằng chứng." |
| 4 | Cuộn xuống bản đồ endpoint và bảng yêu cầu HTTP | "Công cụ trích được 6 endpoint và 5 yêu cầu POST kèm tên tham số — đây là đầu vào cho phần quét động bằng ZAP." |
| 5 | (Nếu còn thời gian) `bash 06_slide/demo/demo.sh --newpipe` | "Trên app thật NewPipe, ở ngưỡng ≥ medium chỉ còn 1 cảnh báo cần đọc, cùng 145 endpoint để kiểm thử tiếp." |

## Khi có sự cố

| Sự cố | Cách xử lý |
|---|---|
| Thiếu apktool/JADX, hoặc quét lỗi | `bash 06_slide/demo/demo.sh --offline` mở báo cáo chạy sẵn trong `06_slide/demo/insecurebankv2/` và `newpipe/` (cùng tham số `--min-confidence medium`) |
| Không có ổ SSD | Mở `report.html` của bản sao repo hoặc bản đã chép sang máy khác; báo cáo là một tệp HTML độc lập |
| Hỏi "chạy lại từ đầu xem có thật không" | `bash 06_slide/demo/demo.sh --cold` xoá cache demo và chạy cả JADX (khoảng 15–20 s) |
