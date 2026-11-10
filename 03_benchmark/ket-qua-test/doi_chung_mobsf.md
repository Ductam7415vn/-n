# Đối chứng apiscan với MobSF trên cùng bộ nhãn (2026-10-04)

## Thiết lập

- MobSF v4.5.4, Docker image ARM64 `opensecurity/mobile-security-framework-mobsf:latest`, chạy cục bộ ở 127.0.0.1:8000,
  **cấu hình mặc định**. Chỉ dùng phân tích tĩnh qua REST API (upload → scan → report_json); không cài, không chạy app.
- apiscan: phiên bản cuối (commit 7135621), phạm vi tự suy — cùng kết quả `final/`.
- Cùng 19 APK thật (SHA-256 trong `04_code/target-app/APK_SOURCES.md`) và InsecureBankv2.
- Lệnh:
  - `04_code/scripts/mobsf_batch.py` → `mobsf/*.json` (bỏ trường `strings` để giảm dung lượng)
  - `python3 04_code/scripts/compare_mobsf.py summary`
  - `python3 04_code/scripts/compare_mobsf.py sample -n 100 --seed 42`
  - `python3 04_code/scripts/compare_mobsf.py eval 03_benchmark/ground-truth/mobsf_sample_labels.json`
- Số liệu đầy đủ: `mobsf/summary.txt`.

**Đơn vị cảnh báo MobSF.** Mỗi cặp (luật, file) ở phần mã, mỗi mục manifest, mỗi mục network security config và mỗi mục
chứng chỉ, **chỉ mức high/warning**. Mức info/secure/good và danh sách "secrets" không tính là cảnh báo. MobSF tự đếm theo
luật (241 luật-app), nhưng người dùng phải xem từng file nên đơn vị (luật, file) gần với khối lượng kiểm tra thật hơn.

## 1. Recall trên InsecureBankv2 (6 mục tĩnh của đáp án)

| Mục | apiscan | MobSF mặc định | MobSF bỏ `com/android/` khỏi SKIP_CLASS_PATH |
|---|---|---|---|
| V01 khoá AES cứng | ✅ | ❌ | ✅ `android_hardcoded` CryptoClass:22 |
| V02 HTTP cleartext | ✅ | ❌ | ❌ |
| V05 AES/CBC + IV tĩnh | ✅ | ❌ | ◐ `cbc_padding_oracle` (báo CBC/padding, không báo IV/khoá) |
| V06 thành phần exported | ✅ | ✅ | ✅ |
| V07 cửa hậu `/devlogin` | ✅ | ❌ | ❌ |
| V11 allowBackup | ✅ | ✅ | ✅ |
| **Tổng** | **6/6** | **2/6** | **3/6 + 1 một phần** |

MobSF mặc định bỏ qua toàn bộ mã của InsecureBankv2 vì `SKIP_CLASS_PATH` chứa `com/android/` (package của app là
`com.android.insecurebankv2`), nên phần phân tích mã trả 0 kết quả. Khi bỏ tiền tố này, MobSF còn báo thêm V04
(`android_world_readable`) và V10 (`android_logging`, mức info).

## 2. Khối lượng cảnh báo trên 19 app thật

| | apiscan | MobSF |
|---|---|---|
| Cảnh báo (đơn vị) | 331 | 1.182 high/warning (+2.177 info, +5.000 "secrets") |
| Trong phạm vi mã app (theo phạm vi apiscan tự suy) | 331 | 642 (54%) |
| Thời gian | phân tích trung vị 0,82 s/app | trung vị 84 s/app, lớn nhất 510 s (Nextcloud), gồm giải nén |

## 3. MobSF có báo các TP mà apiscan tìm được không?

41/57 TP của apiscan được MobSF báo ở mức high/warning. 16 TP còn lại thì MobSF không báo hoặc chỉ báo ở mức info:

- NET-HTTP (9/9): MobSF không có luật cho URL `http://` ghép trong mã. 5 URL nằm trong danh sách URL trích xuất của MobSF
  (không phải cảnh báo).
- WEB-IFACE (5/5): luật `android_webview` của MobSF đòi `setJavaScriptEnabled(true)` và `addJavascriptInterface(` trong
  **cùng một tệp**. Ở Jellyfin và Nextcloud hai lệnh nằm ở hai tệp khác nhau.
- LOG-SENS (2/2): MobSF có báo tệp này, nhưng `android_logging` chỉ ở mức info và báo mọi lệnh log, không chỉ log dữ liệu
  nhạy cảm.

Các nhóm cấu hình (CFG-EXPORT, CFG-BACKUP, NET-CLEAR, NET-NSC, NET-TRUST) MobSF đều báo.

## 4. Precision của MobSF (mẫu ngẫu nhiên, cùng định nghĩa nhãn)

Lấy ngẫu nhiên 100/1.182 đơn vị high/warning (seed 42) và gán nhãn bằng cùng định nghĩa TP/FP và cùng quy ước với nhãn
apiscan. Cấu hình cleartext/tin CA người dùng ở cấp toàn app được tính là TP. Mỗi nhãn kèm lý do trong
`ground-truth/mobsf_sample_labels.json`.

| | TP/mẫu | Precision | KTC 95% (Wilson) |
|---|---|---|---|
| Mọi cảnh báo MobSF | 5/100 | 5,0% | 2,2–11,2% |
| Nguồn mã | 1/75 | 1,3% | 0,2–7,2% |
| *apiscan, chỉ cảnh báo trong mã Java* | 20/258 | 7,8% | 5,1–11,7% |
| Nguồn manifest + NSC + chứng chỉ | 4/25 | 16,0% | — |
| Quy ước nhạy (cấu hình mạng → FP) | 3/100 | 3,0% | 1,0–8,5% |
| **apiscan, mọi cảnh báo** | 57/331 | 17,2% | 13,5–21,7% |
| **apiscan, ≥ medium** | 54/138 | 39,1% | 31,4–47,5% |
| apiscan, quy ước nhạy | 32/331 | 9,7% | 6,9–13,3% |

Hai khoảng tin cậy (MobSF 2,2–11,2%, apiscan 13,5–21,7%) không chồng nhau.

**Theo luật:**
- `android_hardcoded`: 0/36. Toàn tên khoá preference, hằng số `*_KEY`, hoặc chuỗi `toString()` có chữ "key=" hay "password=".
- `android_insecure_random`: 0/12.
- `android_ip_disclosure`: 0/9 (số phiên bản, OID, loopback).
- `android_sql_raw_query`: 0/6 (truy vấn hằng số hoặc có tham số).
- `exported_protected_permission_not_defined`: 0/5. Đều là quyền hệ thống như `MANAGE_DOCUMENTS` hay `BIND_AUTOFILL_SERVICE`.

**TP mà MobSF tìm thấy còn apiscan bỏ sót (1).** Money Manager Ex tạo CSDL tài chính `data.mmb` mặc định ở
`/sdcard/MoneyManagerEx`, và dự phòng ở `getExternalFilesDir`. Mã này bị R8 dời sang package `defpackage`, nằm ngoài phạm
vi apiscan tự suy. Đây là minh chứng cho hạn chế "phạm vi mã" của apiscan.

## 5. Kết luận

- **Recall.** Trên đáp án InsecureBankv2: apiscan 6/6, MobSF mặc định 2/6, MobSF sau khi chỉnh cấu hình 3/6 + 1 một phần.
- **Phủ TP trên app thật.** MobSF phủ 41/57 TP của apiscan. Phần thiếu tập trung ở URL http ghép chuỗi và cầu nối JS
  khác tệp.
- **Precision.** Trên app thật, MobSF ước lượng 5,0% (KTC 2,2–11,2%), thấp hơn apiscan 17,2% (13,5–21,7%) ở mọi mức
  cảnh báo. Số cảnh báo của MobSF gấp 3,6 lần. Phần mã của MobSF gần như toàn báo nhầm (1,3%).
- **Số TP tuyệt đối.** Ước lượng tổng TP của MobSF là 5% × 1.182 ≈ 59, KTC khoảng 26–132, tương đương 57 TP của apiscan.
  Khác biệt chính là apiscan cần kiểm tra ít hơn khoảng 3,6 lần số cảnh báo cho cùng số lỗ hổng thật.

## Hạn chế của phép đối chứng

- Precision MobSF là ước lượng từ mẫu 100, không gán nhãn toàn bộ 1.182 cảnh báo.
- Cùng một người gán nhãn cho cả hai công cụ, và người đó biết nhãn của apiscan. Khi trùng thành phần/tệp đã gán cho
  apiscan thì dùng lại nhãn cũ để nhất quán.
- Precision của apiscan đo trên phiên bản cuối, sau khi luật đã được chỉnh qua các đợt holdout trên chính các app
  này. Còn MobSF không được chỉnh cho tập app này. Trên holdout (đo trước khi chỉnh), precision của apiscan chỉ
  2,8–40%, nên lợi thế của apiscan trên app mới có thể nhỏ hơn con số gộp.
- Đơn vị đếm khác nhau. apiscan báo theo dòng; với MobSF, mỗi luật trên mỗi tệp được tính là một cảnh báo.
- Thời gian MobSF đo trên MacBook Apple M1 16 GB RAM, Docker được cấp khoảng 8 GB và dùng gần hết phần này (swap 12–14 GB), nên chỉ mang tính
  tham khảo.
