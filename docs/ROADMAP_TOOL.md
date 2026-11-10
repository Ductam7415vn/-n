# Lộ trình công cụ APIScan + định nghĩa "output thật"

## "Output thật" nghĩa là gì

Công cụ được coi là có output thật khi một người khác (hoặc BetaSoft) có thể:

1. Chạy **một lệnh** trên một APK và nhận lại báo cáo đọc được ngay:
   `apiscan scan app.apk -o report.html`
2. Báo cáo gồm: danh sách cảnh báo gắn nhãn OWASP + **điểm tin cậy**, **bản đồ endpoint API**, và
   đường dẫn tệp:dòng để kiểm chứng.
3. Chạy được trên **nhiều APK** và cho **bảng tổng hợp** (dashboard).
4. Số báo nhầm đủ thấp để báo cáo dùng được mà không phải lọc tay quá nhiều (precision mục tiêu ≥ 50%
   trên app thật, đo lại trên NewPipe + ≥ 2 app mã nguồn mở khác).

Không tính là output thật: một script chỉ chạy được trên máy mình, in log rời rạc, hoặc một bảng
benchmark tĩnh.

## Các mốc (milestones)

### M1 — Hợp nhất CLI + lọc false positive đã biết  (✅ 2026-10-04 phần tĩnh; `dynamic`/`batch` chưa có)
- Gộp `static_scan.py` + `pipeline.py` dưới một lệnh `apiscan` (subcommand `scan`, `dynamic`, `batch`).
- Tự chạy apktool + JADX bên trong (hiện đang phải giải nén thủ công trước).
- Viết luật lọc 4 loại FP phát hiện trên NewPipe:
  - `NET-HTTP`: bỏ qua dòng `startsWith("http://")`, `replace("http://","https://")`, chỉ giữ khi là
    URL endpoint thật hoặc gán biến base URL.
  - `LOG-SENS`: chỉ cảnh báo khi log chứa **biến** nghi là dữ liệu nhạy cảm, không chỉ vì có từ "secret".
  - `CFG-EXPORT`: bỏ qua component có `intent-filter` chuẩn (LAUNCHER, MEDIA_BUTTON, view/send…).
  - `STO-EXT`: hạ mức xuống "info" khi app khai báo quyền lưu trữ hợp lệ / là app tải file.
- **Ràng buộc:** sau khi lọc, **recall trên InsecureBankv2 phải vẫn = 100%** (test tự động).
- Đo lại precision trên NewPipe (kỳ vọng tăng rõ).

### M2 — Điểm tin cậy + cấu hình  (điểm tin cậy ✅ 2026-10-04; YAML config/suppression ✅ 2026-11-08)
- Mỗi cảnh báo có `confidence` (cao/trung bình/thấp) theo độ chắc của dấu hiệu.
- File cấu hình YAML: bật/tắt quy tắc, danh sách suppression, ngưỡng.
- Phân biệt "lỗ hổng" vs "bề mặt cần rà soát" trong báo cáo.

### M3 — Batch + dashboard  (✅ 2026-11-08: `apiscan batch`, chạy thật 20 APK)
- `apiscan batch dir/*.apk` → quét nhiều app, xuất một dashboard HTML tổng hợp (bảng + biểu đồ).
- Dùng để chạy trên ~20 app mã nguồn mở, ra thống kê "x% app có cấu hình Y".

### M4 — Tích hợp động (chỉ app có phép)  (🔶 2026-11-08: `apiscan dynamic` có, chưa chạy ZAP thật)
- `apiscan dynamic --apk ... --target ...` gọi pipeline MobSF + ZAP, hợp nhất với kết quả tĩnh.
- Dùng bản đồ endpoint từ phân tích tĩnh để **dẫn đường cho ZAP** (ZAP vốn yếu khi tự dò app di động).
- Chỉ dùng trên InsecureBankv2 hoặc app BetaSoft (có phép).

### M5 — Đóng gói + tài liệu + demo ✅ (2026-11-10)
- Đóng gói cài được (`pip install .` hoặc single-file), có `--help` rõ ràng.
- Tài liệu sử dụng + ví dụ.
- Viết **Chương 3 luận văn** hoàn chỉnh từ số liệu thật; cập nhật đề cương theo hướng mới.
- Slide + demo cho hội đồng.

## Chỉ số theo dõi qua các mốc

| Chỉ số | Hiện tại | Mục tiêu |
|---|---|---|
| Recall tĩnh trên InsecureBankv2 | 100% | giữ 100% |
| Precision trên NewPipe (nhãn gán tay) | 33,3% (1/3) — baseline M0: 5,3% (1/19) | ≥ 50% |
| Precision gộp 3 app thật (NewPipe, Tusky, K-9) | 35,7% (5/14) — khi mới thêm 2 app: 17,2% (5/29) | ≥ 50% |
| Số app thật đã chạy | 11 (… + DAVx5, Feeder + holdout 5: Aegis, RedReader) | ≥ 3 |
| **Precision holdout** (app chưa dùng để chỉnh luật) | đợt 9 (Termux, Catima): **14,3% (1/7)**, ≥ medium 25%, high 1/1 — đợt 8 (Briar, MMEX): 25,0% (4/16) — đợt 7: 2,8%, đợt 6: 3,7%, đợt 5: 31,8%, đợt 4: 40,0%, đợt 3: 15,3%, đợt 2: 5,3% | ≥ 50% |
| Precision gộp 9 app thật (tập phát triển) | 41,8% (38/91) | ≥ 50% |
| Một lệnh ra báo cáo | có: `apiscan.py scan app.apk` (tự giải nén, tự suy phạm vi) | có |
| Điểm tin cậy | theo từng cảnh báo — 15 app: high 80,0%, ≥ medium 42,0%, low 1,9%; holdout 7: ≥ medium 7,1%, low 0/65 TP | có |
