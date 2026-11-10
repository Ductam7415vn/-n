# Đo recall của apiscan trên lỗ hổng đã công bố (tiêu chí ghi TRƯỚC khi quét — 2026-11-08)

## Mục đích
Trả lời câu hỏi chưa trả lời được: trên ứng dụng thật, apiscan bỏ sót bao nhiêu lỗ hổng? Nhãn ở Chương 3 chỉ gán cho
cảnh báo công cụ đưa ra, nên không đo được recall. Ở đây đáp án đến từ bên ngoài: CVE do GitHub Security Lab công bố,
độc lập với quá trình chỉnh luật của đồ án (không lấy hai phát hiện của chính apiscan).

## Phiên bản công cụ (đóng băng)
Luật của `static_scan.py` như commit 659f5e7 (bản cuối của Chương 3) + thay đổi 2026-11-08 chỉ thêm fingerprint,
suppression, disable — không đổi luật phát hiện. Quét với cấu hình mặc định (không --config), mọi tầng tin cậy.

## Tập lỗ hổng (10 mục, 5 ứng dụng)
| ID | App | Thành phần (theo advisory) | Cơ chế |
|---|---|---|---|
| CVE-2021-43863 | Nextcloud 3.18.0 | `FileContentProvider` exported, không permission | SQLi qua provider exported |
| CVE-2021-41166 | Nextcloud 3.18.0 | `DiskLruImageCacheFileProvider` có readPermission, thiếu writePermission | Bỏ qua quyền đọc bằng mở ghi |
| GHSL-2022-059 | ownCloud 2.21.1 | `FileContentProvider` exported, không permission | SQLi qua provider exported |
| GHSL-2022-060 | ownCloud 2.21.1 | `ReceiveExternalFilesActivity` | Path traversal khi nhận tệp chia sẻ |
| CVE-2021-41256 | Nextcloud News 0.9.9.62 | `SettingsActivity` exported (intent-filter) | Trả intent nguyên trạng qua setResult → cấp quyền URI |
| CVE-2026-65993 | Wikipedia r/50575 | `MainActivity`, deep link `wikipedia://` | Kiểm tra host bằng endsWith |
| CVE-2026-65994 | Wikipedia r/50575 | `PageActivity` exported (VIEW) | URI của kẻ tấn công vào WebView không kiểm tra domain |
| CVE-2026-65995 | OsmAnd 5.3.10 | `OsmandAidlServiceV2` exported, không permission | Bind AIDL không xác thực |
| CVE-2026-65996 | OsmAnd 5.3.10 | `IntentHelper.parseOpenGpxIntent` (deep link open-gpx) | Path traversal qua tham số name |
| CVE-2026-65997 | OsmAnd 5.3.10 | `MapActivity` exported | Extra nhạy cảm không xác minh bên gọi |

OsmAnd 5.3.10 và Wikipedia r/50575 phát hành trước ngày bản sửa được xác nhận (2026-06-28, 2026-04-14), theo chỉ mục
F-Droid archive. ownCloud 2.21.1, Nextcloud 3.18.0, News 0.9.9.62 là bản mà advisory nêu bị ảnh hưởng.

## Cách chấm (ba mức, chấm cho từng ID)
- **Phát hiện đúng cơ chế**: có cảnh báo (mọi tầng tin cậy) gọi tên đúng thành phần VÀ luật của cảnh báo mô tả đúng nguyên
  nhân (vd CFG-EXPORT cho thành phần exported không permission).
- **Chỉ đúng thành phần**: có cảnh báo hoặc mục "bề mặt tiếp nhận intent" gọi tên đúng thành phần, nhưng luật không mô
  tả nguyên nhân (người rà soát được dẫn tới đúng chỗ, phải tự tìm lỗi).
- **Bỏ sót**: không có gì trỏ tới thành phần.
Recall chính = phát hiện đúng cơ chế / 10. Báo riêng tỉ lệ "đúng cơ chế + đúng thành phần" và riêng tầng ≥ medium.

## Kiểm tra bản đã sửa
Với Nextcloud 3.18.1, News 0.9.9.63, OsmAnd 5.4.11, Wikipedia r/50606: cảnh báo trên thành phần lỗi còn hay mất (đo xem
công cụ có phân biệt được bản đã sửa không). ownCloud không có bản sửa rõ ràng cho GHSL-2022-059 nên không kiểm tra.
