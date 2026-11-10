# Quét động InsecureBankv2 — ZAP dẫn đường bằng phân tích tĩnh (2026-11-08)

Môi trường: backend AndroLabServer (Python 2.7, `04_code/dynamic/backend/Dockerfile`) chạy trong container, chỉ lắng nghe
127.0.0.1; OWASP ZAP 2.17.0 (`zaproxy/zap-stable`) dùng chung network namespace với backend. Mỗi cấu hình chạy trên cặp
container mới (cơ sở dữ liệu sạch). Lệnh: `apiscan.py dynamic` (accessUrl/sendRequest → spider → active scan).

## 1. Bản đồ endpoint tĩnh giúp ZAP được bao nhiêu

| Cấu hình | Đầu vào cho ZAP | Cảnh báo | High | Endpoint API ZAP chạm tới | Thư mục |
|---|---|---|---|---|---|
| A. Không bản đồ | chỉ `http://127.0.0.1:8888` | 3 | 0 | 0/6 | `baseline_khong_ban_do/` |
| B. Bản đồ endpoint | 6 đường dẫn từ `report.json` (GET) | 9 | 0 | 6/6 (chỉ GET, endpoint chỉ nhận POST) | `chi_ban_do/` |
| C. Bản đồ + yêu cầu mẫu | B + 5 POST có tham số (`04_code/dynamic/ib_seed_requests.txt`, tham số lấy từ mã dịch ngược) | 27 | 2 | 6/6 (POST có tham số) | `.` (merged.*) |

Spider của ZAP không tự tìm thêm endpoint nào (backend không có trang HTML liên kết); không có bản đồ thì ZAP không quét
được API. Đường dẫn thôi chưa đủ: các endpoint chỉ nhận POST với tham số form, nên chỉ cấu hình C cho kết quả đáng kể.
Tham số trong C được viết tay từ `BasicNameValuePair` trong mã dịch ngược — bước có thể tự động hoá bằng phân tích tĩnh.

Cảnh báo high của C: **XSS phản xạ** ở `/login` và `/devlogin`, tham số `username` — xác minh lại bằng tay: phản hồi
`Content-Type: text/html` chứa nguyên `<script>alert(1)</script>`. Lỗ hổng này không có trong đáp án V01–V12. Các cảnh báo
medium/low còn lại là thiếu header (CSP, X-Frame-Options, X-Content-Type-Options).

## 2. Đối chiếu với các mục động của đáp án

| Mục | ZAP tự động (C) | Kiểm chứng thủ công theo bản đồ endpoint | Bằng chứng (phản hồi máy chủ) |
|---|---|---|---|
| V07 cửa hậu /devlogin | không | ✅ | `devadmin` + mật khẩu bất kỳ → `Correct Credentials` |
| V08 BOLA (API1) | không | ✅ | dinesh chuyển từ tài khoản 999999999 của jack → `Success` |
| V09 xác thực hỏng (API2) | không | ✅ | `/changepassword username=jack` không xác thực → đổi được, đăng nhập bằng mật khẩu mới; `/login` trả "User Does not Exist" khác "Wrong Password" → dò tên người dùng |
| V12 chính sách mật khẩu yếu | không | ✅ | mật khẩu mới `a` (1 ký tự) được chấp nhận |
| V02 cleartext | — | ✅ | toàn bộ API trên `http://` |

ZAP (quét tự động theo chữ ký) không phát hiện lỗi nghiệp vụ: phân quyền đối tượng (V08), luồng đổi mật khẩu (V09), chính
sách mật khẩu (V12). Bốn mục này chỉ xác nhận được bằng yêu cầu có chủ đích — bản đồ endpoint và tham số từ phân tích tĩnh
cho biết cần gửi yêu cầu nào.

Lệnh kiểm chứng thủ công (chỉ trên container cục bộ):
```
curl -X POST --data 'username=devadmin&password=x' http://127.0.0.1:8888/devlogin
curl -X POST --data 'username=dinesh&password=Dinesh%40123%24&from_acc=999999999&to_acc=888888888&amount=5' http://127.0.0.1:8888/dotransfer
curl -X POST --data 'username=jack&newpassword=a' http://127.0.0.1:8888/changepassword
curl -X POST --data 'username=jack&password=a' http://127.0.0.1:8888/login
curl -X POST --data 'username=khongtontai&password=x' http://127.0.0.1:8888/login
```

Hạn chế: một ứng dụng có chủ đích; ZAP cấu hình mặc định (không chính sách quét tuỳ chỉnh, không xác thực theo phiên);
Burp Suite và Frida của ma trận Chương 2 vẫn chưa chạy.

## 3. Yêu cầu mẫu tự trích từ mã (2026-11-08, tối muộn)

`request_extract.py` trích phương thức + đường dẫn + tên tham số từ `new HttpPost(... "/path")` + `BasicNameValuePair`
(và Retrofit `@POST/@Field/@Query/@Path/@Body`) vào `report.json["requests"]`; `apiscan dynamic` tự sinh yêu cầu mẫu với
giá trị giả (`apiscan`, hoặc `1` cho tham số dạng số). Trên InsecureBankv2: 5/5 yêu cầu, khớp từng tham số với tệp viết tay
(test `test_request_extract.py`). Chạy trên cặp container mới, **không** dùng `--seed-requests`:

| Cấu hình | Đầu vào cho ZAP | Cảnh báo | High | Thời gian | Thư mục |
|---|---|---|---|---|---|
| C. Bản đồ + yêu cầu mẫu viết tay | như mục 1 | 27 | 2 | không đo | `.` |
| D. Bản đồ + yêu cầu tự trích | 6 URL + 5 POST tự sinh, giá trị giả | 26 | 2 | 123 s (cả lệnh) | `tu_trich/` |

Hai cảnh báo high giống hệt C: XSS phản xạ `/login`, `/devlogin` (tham số `username`). Khác biệt nằm ở mức low/medium:
D có thêm 2 cảnh báo `/dotransfer` trả HTTP 500 (Application Error Disclosure, Debug Error Messages) — giá trị giả
`username=apiscan` không tồn tại làm máy chủ lỗi; thiếu 1 cảnh báo anti-clickjacking, 1 X-Content-Type-Options và mục info
User Agent Fuzzer. Giá trị tham số (kể cả thông tin đăng nhập hợp lệ) không trích được từ mã tĩnh.

Trên 16 app đã giải nén (cùng phạm vi tự suy): số cảnh báo không đổi so với `batch_20apk`; trích được yêu cầu ở 3 app —
InsecureBankv2 5 (HttpClient), Wikipedia 33 (Retrofit, 28 có tham số), Conversations 2 (Retrofit). Tusky dùng Retrofit nhưng R8
đổi tên cả package `retrofit2` lẫn annotation → 0. OkHttp builder (`FormBody`, `HttpUrl`) chưa hỗ trợ.
