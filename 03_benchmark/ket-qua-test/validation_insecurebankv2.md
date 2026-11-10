# Kiểm chứng độ chính xác của static_scan.py trên InsecureBankv2

> Chạy ngày 2026-10-03. Đầu vào: APK đã giải nén bằng apktool 2.9.3 + dịch ngược bằng JADX 1.5.0.
> Công cụ chỉ đọc tệp, không gửi yêu cầu mạng. APK SHA-256 `b18af2a0…94a4`.

Mục đích: đo xem công cụ tự viết phát hiện đúng đến đâu, bằng cách đối chiếu với đáp án chuẩn
V01–V12 (Bảng 2.10, Báo cáo đợt 2). Đây chính là bước làm cho `static_scan.py` trở thành một
đóng góp có kiểm chứng, chứ không chỉ là script chạy cho có.

## 1. Tổng quan kết quả

- Tổng **24 cảnh báo**: 10 mức cao, 13 trung bình, 1 thấp.
- Theo OWASP: M1=3, M5=4, M8=9, M9=6, M10=1, M4=1.
- Trích được **bản đồ 6 endpoint**: `/login`, `/devlogin`, `/getaccounts`, `/dotransfer`, `/changepassword`, `/Statements_`.

## 2. Đối chiếu với đáp án V01–V12

| Mã | Lỗ hổng | Nhóm (đáp án) | Công cụ phát hiện? | Bằng chứng |
|----|---------|---------------|--------------------|-----------|
| V01 | Khoá viết cứng | Tĩnh | ✅ TP | `CryptoClass.java:22` (CRY-KEYLIT) |
| V02 | HTTP không mã hoá | Cả hai | ✅ TP | `protocol="http://"` ×3 (NET-HTTP) + targetSdk=22 (NET-SDK) |
| V03 | Không có cert pinning | Động | ❌ FN | Là lỗi "thiếu", công cụ tĩnh hiện chưa suy ra được |
| V04 | Lưu trữ không an toàn | Động | ✅ TP | `MyBroadCastReceiver.java:21` WORLD_READABLE (STO-PREF-WORLD) |
| V05 | Mật mã yếu | Tĩnh | ✅ TP | `CryptoClass.java:23` IV tĩnh (CRY-IV0) |
| V06 | Thành phần exported | Tĩnh | ✅ TP | 6× CFG-EXPORT |
| V07 | Cửa hậu /devlogin | Cả hai | ✅ TP | `DoLogin.java:101` + endpoint `/devlogin` (API-HIDDEN) |
| V08 | BOLA/IDOR | Động | — | Lỗ hổng phía server, ngoài tầm phân tích tĩnh |
| V09 | Xác thực bị phá vỡ | Động | — | Phía server |
| V10 | Rò rỉ qua log | Động | ✅ TP | `DoLogin.java:117` (LOG-SENS) |
| V11 | allowBackup | Tĩnh | ✅ TP | `AndroidManifest.xml:15` (CFG-BACKUP) |
| V12 | Chính sách mật khẩu yếu | Động | — | Logic phía server |

## 3. Các chỉ số đo được

**Recall trên nhóm lỗ hổng tĩnh (đáp án ghi "Tĩnh" + "Cả hai" = V01,V02,V05,V06,V07,V11):**
- Phát hiện 6/6 → **Recall = 100%** trên phạm vi công cụ tĩnh được kỳ vọng.
- **Vượt kỳ vọng:** còn phát hiện thêm V04 và V10 (đáp án xếp nhóm "Động"), vì bản thân mã nguồn
  đã để lộ dấu hiệu.

**Precision:**
- 24/24 cảnh báo đều ứng với một điểm yếu có thật (sau khi sửa quy tắc) → **Precision ≈ 100%** trên app này.
- Trong lần chạy đầu có **1 báo nhầm**: hằng `PASSWORD_PATTERN` (biểu thức chính quy kiểm tra độ
  mạnh mật khẩu) bị nhận nhầm là khoá viết cứng. Đã sửa quy tắc để loại chuỗi chứa ký tự regex →
  báo nhầm biến mất. *Đây là một tình huống precision điển hình nên đưa vào luận văn.*

**Không bịa:** công cụ **không** đưa ra cảnh báo sai cho các lỗ hổng động (V08, V09, V12) — đúng
như kỳ vọng của một công cụ tĩnh.

**Giới hạn thấy rõ:** V03 (thiếu certificate pinning) không phát hiện được, vì đó là lỗi "vắng
mặt một cơ chế" — khó suy ra bằng dấu hiệu tĩnh. Đây là ranh giới năng lực cần nêu thẳng.

## 4. Ý nghĩa cho đồ án

- `static_scan.py` phủ được **toàn bộ nhóm lỗ hổng tĩnh** của đáp án, với độ chính xác cao và có
  khả năng trích bản đồ endpoint — đầu vào cho bước kiểm thử động (khi có sự cho phép của chủ app).
- Quá trình xuất hiện-rồi-sửa một báo nhầm cho thấy phương pháp kiểm chứng hoạt động: có đáp án để
  đo, thấy sai thì chỉnh quy tắc, đo lại. Đây là câu chuyện kỹ thuật có chiều sâu để trình bày.
- Bước tiếp theo: chạy trên một ứng dụng mã nguồn mở để đo precision ngoài môi trường "có chủ đích",
  nơi mã thật phức tạp hơn và dễ phát sinh báo nhầm hơn.
