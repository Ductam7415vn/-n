# Áp dụng static_scan.py lên ứng dụng mã nguồn mở thật: NewPipe

> Chạy ngày 2026-10-03. App: NewPipe 0.29.1 (`org.schabi.newpipe`), tải từ F-Droid.
> APK SHA-256 `1d66d19e…b7e8`, 11,5 MB. Mã nguồn công khai trên GitHub → đối chiếu được từng cảnh báo.
> Công cụ chỉ đọc tệp, không gửi yêu cầu mạng. Lý do chọn NewPipe: mã nguồn mở (hợp pháp để phân
> tích), có gọi nhiều API (YouTube/PeerTube/SoundCloud) nên kiểm tra được khả năng trích endpoint.

> **Đính chính (2026-10-03, sau khi lập bộ nhãn gán tay):** bản đầu ghi 17 cảnh báo / 146 endpoint /
> ≈6% — số đó từ một phiên bản quy tắc cũ, không tái lập được bằng mã hiện tại. Số dưới đây chạy lại
> bằng `static_scan.py` hiện tại (`m0_baseline/np.json`) và chấm bằng nhãn ở
> `03_benchmark/ground-truth/newpipe_labels.json` qua `test_groundtruth.py`.

## 1. Số liệu thô

- **19 cảnh báo**: 6 cao, 12 trung bình, 1 thấp.
- **145 endpoint** trích được (ví dụ `/api/v1/videos/`, `/api/v1/search/videos`, `/channel/…`).
- So với InsecureBankv2 (app có lỗ hổng có chủ đích): 24 cảnh báo, precision ~100%.

## 2. Đối chiếu từng cảnh báo với mã nguồn gốc

| Cảnh báo | Số lượng | Thực chất sau khi xem mã | Phân loại |
|----------|---------|---------------------------|-----------|
| CFG-EXPORT | 6 | MainActivity (có intent-filter LAUNCHER), RouterActivity, MediaButtonReceiver, PanicResponderActivity… — **đều buộc phải exported** để app hoạt động | Cố ý, không phải lỗ hổng |
| STO-EXT | 4 | FilePickerActivityHelper, StoredFileHelper — truy cập bộ nhớ ngoài là **chức năng chính** (người dùng chọn thư mục tải video) | Cố ý |
| NET-HTTP | 6 | 3 là mã **nâng cấp/chuẩn hoá http→https** (`"https://".concat(...)`, `startsWith("http://")`, `replace("http://","https://")`) → **mã bảo mật tốt bị báo nhầm**; 3 là URI namespace XML (`xmlpull.org`, `schemas.android.com`) — không phải kết nối mạng | ❌ Báo nhầm |
| LOG-SENS | 1 | `Log.i("NavigationHelper", "You unlocked a secret unicorn.")` — easter egg, khớp từ "secret" | ❌ Báo nhầm |
| WEB-JS | 1 | `ReCaptchaActivity` bật JavaScript — **cần thiết** để hiển thị trang reCaptcha | Cố ý |
| CFG-BACKUP | 1 | `allowBackup="true"` — điểm yếu cấu hình **có thật** (dù NewPipe không lưu dữ liệu nhạy cảm nên rủi ro thấp) | Điểm yếu thật (nhẹ) |

## 3. Kết quả: so sánh hai môi trường

| | InsecureBankv2 (có chủ đích) | NewPipe (app thật) |
|---|---|---|
| Tổng cảnh báo | 24 | 19 |
| Điểm yếu thật (TP theo nhãn) | 24 | **1** (allowBackup) |
| Cố ý / không phải lỗ hổng (FP `intended`) | 0 | 9 |
| Báo nhầm hẳn (FP `pattern`) | 1 (đã sửa trước khi gán nhãn) | 9 |
| Precision như "lỗ hổng" | 100% (24/24) | **5,3% (1/19)** |
| Endpoint trích được | 6 | 145 |

## 4. Đây chính là kết quả nghiên cứu có giá trị

Khoảng cách precision 100% → 5,3% khi chuyển từ app có chủ đích sang app thật **chính là phát hiện
đáng giá nhất** của đồ án, chứ không phải điểm trừ:

1. **Phân tích tĩnh theo dấu hiệu có recall cao nhưng precision thấp trên app thật.** Phần lớn cảnh
   báo trên app thật là hành vi cố ý (thành phần buộc phải exported, truy cập bộ nhớ là chức năng
   chính) chứ không phải lỗ hổng.
2. **Có trường hợp báo nhầm ngược đời: công cụ gắn cờ chính mã bảo mật tốt.** Ba cảnh báo NET-HTTP
   đều rơi vào đoạn mã *nâng cấp http lên https* — tức công cụ phạt code đang làm điều đúng. Đây là
   ví dụ kinh điển về hạn chế của kỹ thuật so khớp từ khoá.
3. **Vì vậy không thể bỏ bước con người rà soát.** Kết quả củng cố cho quy trình đề xuất: dùng công
   cụ để sàng lọc nhanh và lập bản đồ, rồi con người xác minh — không dùng công cụ để kết luận tự động.
4. **Giá trị ổn định nhất của công cụ trên app thật là bản đồ endpoint** (145 endpoint), phục vụ
   định hướng kiểm thử (có phép), chứ không phải danh sách lỗ hổng.

## 5. Hướng cải thiện precision (đưa vào "hướng phát triển")

- Bỏ qua thành phần exported có intent-filter chuẩn (LAUNCHER, media button…).
- Phân biệt *dùng* http với *kiểm tra/thay thế* http (bỏ qua các dòng `startsWith`, `replace`).
- Lọc log easter egg / chuỗi không phải dữ liệu nhạy cảm thật.
- Chấm điểm tin cậy cho mỗi cảnh báo thay vì nhị phân có/không.

## 6. Lưu ý đạo đức & pháp lý

- Chỉ phân tích **tĩnh** trên app **mã nguồn mở** (hợp pháp để đọc và dịch ngược).
- **Không** quét động, không gửi yêu cầu tới máy chủ của NewPipe hay bên thứ ba.
- allowBackup là cấu hình công khai trong APK; không có dữ liệu nhạy cảm nào bị trích xuất.
