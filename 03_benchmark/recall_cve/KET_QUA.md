# Kết quả recall trên 10 lỗ hổng đã công bố (2026-11-08)

Tiêu chí: `TIEU_CHI.md` (ghi trước khi quét). Báo cáo apiscan từng APK: `bao_cao/`. Dữ liệu chấm: `ket_qua.json`.
APK lấy từ F-Droid (repo/archive), SHA-256 khớp chỉ mục F-Droid.

| Mức | Số CVE | Tỉ lệ |
|---|---|---|
| Phát hiện đúng cơ chế (mọi tầng tin cậy) | 3 | 30% |
| — trong đó ở tầng ≥ medium | 2 | 20% |
| Chỉ trỏ đúng thành phần (cảnh báo lệch lý do hoặc mục bề mặt tiếp nhận) | 7 | 70% |
| Bỏ sót hoàn toàn | 0 | 0% |

Ba CVE phát hiện đúng đều là **provider exported thiếu permission** (lỗi cấu hình đọc được từ Manifest). Bảy CVE còn lại là
lỗi **logic xử lý dữ liệu đầu vào** của thành phần có lý do để exported (deep link, VIEW/SEND, AIDL của giao thức với
app khác): kiểm tra host bằng `endsWith`, path traversal theo tham số, trả intent nguyên trạng, không xác thực bên gọi
AIDL. Mọi thành phần này đều có mặt trong mục "bề mặt tiếp nhận intent" → báo cáo dẫn người rà soát tới đúng chỗ, nhưng
luật dựa trên dấu hiệu không tự kết luận được.

Hai quan sát dẫn tới hướng cải tiến (phân tích SAU khi xem kết quả — không dùng để sửa số recall ở trên):
1. CVE-2021-43863 bị xếp **low** vì mã provider có gọi API kiểm tra app gọi. Có API kiểm tra không có nghĩa là kiểm
   tra đúng — quy tắc hạ tin cậy này làm mất một CVE thật ở ngưỡng khuyến nghị ≥ medium.
2. CVE-2026-65995 là service exported không permission, nhưng vì nhận action tuỳ biến nên bị xếp là "giao thức với app
   bên thứ ba". Nâng riêng nhóm *service + action tuỳ biến + không permission* thành cảnh báo chỉ thêm 6 cảnh báo trên
   19 app thật (đếm từ `ket-qua-test/batch_20apk`). Cần một đợt holdout mới để đo tác động lên precision.

Bản đã sửa: công cụ phân biệt được 1/1 bản sửa dạng cấu hình (thêm `android:permission`), không phân biệt được các bản sửa
logic (News, OsmAnd, Wikipedia) — đúng với giới hạn của phân tích tĩnh dựa trên dấu hiệu.

Hạn chế: tập nhỏ (10 CVE, 5 app), thiên về lỗi thành phần exported vì nguồn chính (GitHub Security Lab) tập trung vào
nhóm này; không có CVE về mật mã, lưu trữ, log để đo recall các luật đó.
