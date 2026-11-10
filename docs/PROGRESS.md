# Sổ tiến độ (PROGRESS)

> Cập nhật file này ở CUỐI mỗi phiên: việc đã làm, số liệu mới, việc tiếp theo.
> Định dạng: ngày — việc — kết quả/đo được — file minh chứng.

## Trạng thái tổng (2026-10-03)

- Giai đoạn: **M0 xong → bắt đầu M1** (hợp nhất CLI + lọc FP).
- Công cụ: `static_scan.py` (tĩnh, chạy thật). `pipeline.py` (động) **không còn trên máy** — cần tìm lại.
- Số liệu thật: InsecureBankv2 (recall 100% tĩnh), NewPipe (precision 5,3% = 1/19, nhãn gán tay).
- Chặn ngoài: cần máy Mac cho MobSF/ZAP/emulator; GVHD đã cho phép đổi hướng (2026-10-04).

## Nhật ký

- **2026-10-03**
  - Viết `static_scan.py` (quét tĩnh, gắn nhãn OWASP, trích endpoint). → `04_code/scripts/`
  - Kiểm chứng InsecureBankv2: recall 6/6 nhóm tĩnh = 100%, precision ~100% (sửa 1 FP `PASSWORD_PATTERN`).
    → `03_benchmark/ket-qua-test/validation_insecurebankv2.md`
  - Chạy thật NewPipe 0.29.1: 17 cảnh báo, 146 endpoint, precision ~6%; FP gồm mã http→https, log
    easter egg, exported hợp lệ, bộ nhớ ngoài. → `.../realworld_newpipe.md`
  - Chốt đổi trọng tâm sang xây công cụ `apiscan`. Lập bộ handoff + harness.

- **2026-10-03 (phiên 2)**
  - `git init` riêng cho `Đồ án/` + `.gitignore` (bỏ `OUT_*`, `*.apk`); SHA-256 APK ghi ở
    `04_code/target-app/APK_SOURCES.md`.
  - Chạy lại `static_scan.py` trên 2 app → trùng khớp 100% với `m0_baseline/` (24 & 19 cảnh báo).
  - Gán nhãn tay từng cảnh báo (đối chiếu mã/manifest) → `03_benchmark/ground-truth/*_labels.json`.
  - Viết lại `test_groundtruth.py`: precision từ nhãn, báo cảnh báo chưa nhãn, FAIL khi mất TP; V02/V06
    chấm chặt hơn (V06 đòi đủ 6 thành phần). Kết quả: recall IB 6/6, precision IB 100% (24/24),
    NewPipe **5,3% (1/19)** — thay cho 58% của công thức cũ. → `m0_baseline/test_output.txt`
  - Đính chính `realworld_newpipe.md` (17/146/≈6% cũ không tái lập được → 19/145/5,3%).

- **2026-10-03 (phiên 3) — M1: lọc FP `NET-HTTP`**
  - `static_scan.py`: `NET-HTTP` bỏ qua URI namespace/schema (dùng lại `URL_IGNORE`) và chuỗi `"http://"` trơn
    làm đối số hàm xử lý chuỗi (`startsWith`/`replace`/…, mẫu kiểm tra/nâng cấp http→https); vẫn giữ
    `replace("https://","http://")` (hạ cấp). Luật tổng quát, không dựa vào tên class của app.
  - Recall IB 6/6 giữ nguyên; precision IB 100% (24/24); NewPipe **5,3% (1/19) → 7,7% (1/13)**: hết 6/6 FP
    NET-HTTP, không mất TP, không phát sinh cảnh báo chưa nhãn; endpoint map không đổi (6 / 145).
    → `03_benchmark/ket-qua-test/m1_net-http/`

- **2026-10-03 (phiên 4) — M1: lọc FP `CFG-EXPORT`**
  - Đọc Manifest bằng XML parser; tính cả exported **ngầm định** (intent-filter + targetSdk<31, provider + targetSdk<17).
  - Vẫn là cảnh báo: exported không permission mà **không có intent-filter**, hoặc nhận **action tuỳ biến do
    chính app tự gửi** (`setAction`/`new Intent`) — kênh nội bộ bị mở. Còn lại (LAUNCHER, intent hệ thống/chuẩn,
    action của app bên thứ ba) chuyển sang mục **`attack_surface`** ("bề mặt tiếp nhận intent") trong JSON/HTML,
    không tính là lỗ hổng nhưng vẫn liệt kê để rà soát.
  - Recall IB 6/6 (V06 đủ 6 thành phần; `MyBroadCastReceiver` giữ nhờ app tự gửi `theBroadcast`); precision IB
    100% (24/24); NewPipe **7,7% (1/13) → 14,3% (1/7)**: hết 6/6 FP CFG-EXPORT, 6 thành phần sang bề mặt.
    IB phát hiện thêm `LoginActivity` exported ngầm định (LAUNCHER → bề mặt). → `ket-qua-test/m1_cfg-export/`

- **2026-10-03 (phiên 5) — thêm 2 app thật làm tập kiểm tra độc lập (holdout)**
  - Tải từ F-Droid: Tusky 32.2 (`com.keylesspalace.tusky_142.apk`), K-9 Mail 23.1 (`com.fsck.k9_39045.apk`);
    SHA-256 ở `04_code/target-app/APK_SOURCES.md`. Chỉ phân tích tĩnh.
  - Gán nhãn tay 22 cảnh báo → `ground-truth/tusky_labels.json` (1 TP/6), `k9mail_labels.json` (3 TP/16).
  - Precision: NewPipe 14,3% (1/7), Tusky 16,7% (1/6), K-9 18,8% (3/16) → **gộp 17,2% (5/29)**, macro 16,6%.
    Trên 2 app holdout (chưa dùng để viết luật): 18,2% (4/22). → `ket-qua-test/m1_4apps/`
  - FP trên holdout theo luật: LOG-SENS 9 (thông điệp tĩnh chứa 'token'), CRY-HASH 2 (MD5 do giao thức
    CRAM-MD5/APOP), NET-HTTP 2 (replace bị R8 đổi tên; link hiển thị), STO-EXT 2, NET-NSC 1 (domain-config
    .onion), WEB-JS 1, CFG-EXPORT 1 (provider tự kiểm tra chữ ký trong mã).
  - TP đáng chú ý: Tusky `CropImageActivity` (thư viện CanHub) exported không cần thiết; K-9 cho phép
    cleartext toàn cục + tin CA người dùng.
  - Giới hạn: K-9 có mã ở `app.k9mail.*`, `net.thunderbird.*` nhưng chỉ quét `com.fsck.k9` (package manifest).

- **2026-10-03 (phiên 6) — M1: lọc FP `LOG-SENS`**
  - Chỉ cảnh báo khi log in ra GIÁ TRỊ nhạy cảm: biến/biểu thức ngoài chuỗi mang tên nhạy cảm, hoặc chuỗi
    chứa từ khoá được nối với giá trị (`"token=" + x`) / có placeholder (`"password %s"`). Bỏ qua thông điệp
    cố định chỉ chứa từ khoá. Tách đối số bằng khớp ngoặc (sửa lỗi `[^)]*` dừng ở `)` đầu tiên).
  - Recall IB 6/6 (V10 `DoLogin` vẫn bắt); precision IB 100%. NewPipe 14,3% → 16,7% (1/6), Tusky 16,7% (không
    đổi), K-9 18,8% → **42,9% (3/7)**. **Gộp 3 app thật: 17,2% → 26,3% (5/19)**, macro 25,4%.
    Không phát sinh cảnh báo mới; endpoint không đổi. → `ket-qua-test/m1_log-sens/`
  - Giới hạn: chỉ xét `Log.*` trên một dòng; chưa xét Timber/println/logger tuỳ biến.

- **2026-10-04 — M1: lọc FP `STO-EXT`**
  - Chỉ cảnh báo khi dòng GHÉP thư mục bộ nhớ ngoài với tên tệp (`new File(ext, name)`, `ext + "/..."`,
    `"file://" + ext`) — app tự tạo tệp ở vùng dùng chung. Bỏ qua tham chiếu thư mục trơn (gốc bộ chọn tệp,
    so sánh đường dẫn) và chuỗi tên quyền `*_EXTERNAL_STORAGE`. Mở rộng phủ `getExternalCacheDir`.
  - Mở rộng phủ sinh 1 cảnh báo mới trên NewPipe (`PlayerDataSource` cache ExoPlayer) → gán nhãn FP.
  - Recall IB 6/6 (4 STO-EXT V04 giữ nguyên); NewPipe 16,7% → 33,3% (1/3), Tusky 16,7% → 25,0% (1/4), K-9
    42,9% (không đổi). **Gộp 3 app thật: 26,3% → 35,7% (5/14)**, macro 33,7%. → `ket-qua-test/m1_sto-ext/`
  - Giới hạn: đường dẫn ghép qua nhiều dòng (biến trung gian) bị bỏ sót; rà 3 app thật không thấy tệp nào vừa
    lấy thư mục ngoài vừa ghi tệp. Không theo dõi biến vì sẽ đưa lại FP (`StoredFileHelper` của NewPipe).

- **2026-10-04 — holdout đợt 2: AntennaPod 3.12.2 + Nextcloud 35.0.0** (luật đóng băng ở `a84dc9e`)
  - Gán nhãn tay 169 cảnh báo → `ground-truth/antennapod_labels.json` (5 TP/129), `nextcloud_labels.json` (4 TP/40).
  - **Precision holdout: AntennaPod 3,9%, Nextcloud 10,0% → gộp 5,3% (9/169).** Tập phát triển (NewPipe/Tusky/K-9)
    vẫn 35,7% → luật lọc M1 KHÔNG tổng quát hoá như số trên tập phát triển gợi ý.
  - Nguyên nhân chính: `CRY-KEYLIT` (chưa từng bị thử thách trên 3 app trước) báo nhầm 141/160 FP — khớp chữ
    key/pass/token trong TÊN hằng (`KEY_*`, tên cột DB, khoá SharedPreferences). Bỏ riêng luật này: 32,1% (9/28)
    — chỉ là phân tích, chưa phải kết quả đo của công cụ.
  - FP khác trên holdout: NET-HTTP 5 (namespace RSS thiếu trong URL_IGNORE), CRY-HASH 5 (MD5/SHA-1 không dùng cho
    bảo mật), CFG-EXPORT 4 (SSO/tự động hoá có kiểm tra trong mã), LOG-SENS 2, CRY-WEAK 1 (RSA/ECB/OAEP), STO-EXT 1,
    CFG-BACKUP 1 (có backupAgent riêng).
  - TP đáng chú ý: Nextcloud `FileContentProvider` exported, bỏ kiểm tra người gọi cho bảng `filelist`; AntennaPod
    chép DB hỏng (có mật khẩu feed) ra external, mặc định thêm `http://`.
  - FN đã biết: AntennaPod nhúng cứng API key/secret PodcastIndex (BuildConfig + literal trong lời gọi) — CRY-KEYLIT
    không bắt. Ghi ở `known_false_negatives` trong file nhãn.
  - Recall IB 6/6 giữ nguyên. → `ket-qua-test/m1_holdout2/` (`test_output_all.txt`, `test_output_holdout.txt`)

- **2026-10-04 — M1: lọc FP `CRY-KEYLIT`** (AntennaPod/Nextcloud từ đây thành tập PHÁT TRIỂN, không còn holdout)
  - Bỏ qua hằng là TÊN khoá khi giá trị dạng định danh (không dấu cách, không dãy ≥3 chữ số): câu SQL, tên đủ
    package, tên biến `KEY_/PREF_/EXTRA_/ARG_/COLUMN_*`, hoặc giá trị trùng từ với tên biến (trừ key/pass/token…).
    Passphrase có dấu cách (IB) và chuỗi ngẫu nhiên nhiều số vẫn bị bắt.
  - CRY-KEYLIT quét thêm `BuildConfig.java` (các luật khác vẫn bỏ qua) → bắt được API key PodcastIndex của
    AntennaPod (FN trước đó) → gán TP. Secret đi kèm (literal trong `sha1(...)`) vẫn là FN đã biết.
  - Hết 141/141 FP CRY-KEYLIT; recall IB 6/6; không mất TP. AntennaPod 3,9% → 30,0% (6/20), Nextcloud 10,0% →
    44,4% (4/9). **Gộp 5 app thật: 34,9% (15/43)**, macro 35,1%. → `ket-qua-test/m1_cry-keylit/`
  - Lưu ý phương pháp: cả 5 app thật đều đã dùng để chỉnh luật → cần holdout mới để đo tổng quát hoá.

- **2026-10-04 — holdout đợt 3: Conversations 2.20.4 + Jellyfin 2.7.3** (luật đóng băng ở `19f2943`)
  - Gán nhãn tay 85 cảnh báo → `ground-truth/conversations_labels.json` (6 TP/75), `jellyfin_labels.json` (7 TP/10).
    Thêm trường `borderline` cho nhận định có thể tranh luận (5 TP: 4 WEB-IFACE Jellyfin, 1 STO-EXT Conversations).
  - **Precision holdout 3: Conversations 8,0%, Jellyfin 70,0% → gộp 15,3% (13/85); chặt (borderline→FP) 9,4% (8/85).**
    So với holdout 2 trước khi sửa luật: 5,3%. Gộp cả 7 app thật: 21,9% (28/128), macro 36,2%.
  - FP holdout 3 theo luật: NET-HTTP 42 (namespace XMPP `jabber.org/protocol/...` — cùng lớp lỗi namespace như
    RSS ở AntennaPod: danh sách URL_IGNORE liệt kê tay không tổng quát hoá), CRY-KEYHARD 11 (khoá sinh lúc chạy:
    SCRAM/HMAC, OMEMO), STO-EXT 10, LOG-SENS 3, CRY-HASH 2, CFG-EXPORT 2, CFG-BACKUP 1, WEB-JS 1.
  - TP đáng chú ý: Conversations log ICE password (toString của Credentials), CanHub CropImageActivity exported
    (lần 2, sau Tusky); Jellyfin backup cả cookie/localStorage WebView không mã hoá, JS bridge mở cho nội dung server.
  - Phạm vi: Conversations có 430 tệp ở `im.conversations.android` không được quét. → `ket-qua-test/m1_holdout3/`

- **2026-10-04 — M1: `NET-HTTP` theo ngữ cảnh** (Conversations/Jellyfin từ đây thành tập PHÁT TRIỂN)
  - Thay danh sách domain bằng ngữ cảnh literal: hàm bao quanh là hàm XML/namespace (findChild, hasFeature,
    setAttribute…) hoặc so sánh chuỗi; URI dạng đặc tả (#, /protocol/, /ns/, /drafts/, .dtd…); hằng namespace,
    dòng có xmlns/urn:; link mở bằng trình duyệt (intent VIEW); "http://" trơn cùng "https://" (chuẩn hoá scheme).
    Hạ cấp https→http, `protocol = "http://"`, `"http://" + url` vẫn bị bắt.
  - NET-HTTP FP: Conversations 42→0, AntennaPod 5→0, Tusky 1→0; còn 1 (K-9 danh sách link thư viện). TP giữ đủ 4.
  - Recall IB 6/6. **Gộp 7 app thật: 21,9% → 35,0% (28/80)**, macro 40,3%. Conversations 8,0% → 18,2%.
    → `ket-qua-test/m1_net-http-ctx/`. Cả 7 app đã dùng để chỉnh luật → cần holdout đợt 4.

- **2026-10-04 — holdout đợt 4: DAVx5 4.5.20-ose + Feeder 2.23.2** (luật đóng băng ở `3fd2ccb`)
  - Gán nhãn tay 25 cảnh báo → `ground-truth/davx5_labels.json` (3 TP/6), `feeder_labels.json` (7 TP/19, 2 borderline).
  - **Precision holdout 4: DAVx5 50,0%, Feeder 36,8% → gộp 40,0% (10/25); chặt 32,0% (8/25).**
    Xu hướng holdout: đợt 2 5,3% → đợt 3 15,3% → đợt 4 40,0%. Gộp 9 app thật: 36,2% (38/105), macro 41,0%.
  - Mẫu nhỏ (25 cảnh báo). Feeder không sinh FP namespace RSS nhưng vì parser RSS nằm ngoài package app → chưa phải
    bằng chứng đầy đủ cho NET-HTTP theo ngữ cảnh.
  - FP holdout 4: NET-HTTP 6 (new URL("http://") làm placeholder/kiểm tra cú pháp), CRY-KEYHARD 3, CFG-EXPORT 4
    (1 do R8 gộp mã thư viện UnifiedPush vào package app → heuristic 'app tự gửi action' sai), WEB-JS/IFACE 2 (trang cục bộ).
  - TP đáng chú ý: Feeder nhúng cứng Basic Auth server đồng bộ; PreviewActivity (debug) lọt vào release.
  - ⚠️ Một phát hiện mức nghiêm trọng cao ([ẩn danh A]). Ẩn danh: lỗ hổng đang được công bố có trách nhiệm cho nhà phát triển; chi tiết sẽ được bổ sung sau khi bản sửa được phát hành.

- **2026-10-04 — M1: `CRY-KEYHARD` bằng phân tích luồng trong tệp** (DAVx5/Feeder từ đây thành tập PHÁT TRIỂN)
  - Chỉ cảnh báo SecretKeySpec khi byte khoá truy về hằng trong cùng tệp: literal chuỗi, mảng byte literal,
    `.getBytes()`, `Base64.decode`/hex của hằng; lan truyền qua gán (theo phạm vi hàm, tránh trùng tên `bArr` của JADX)
    và qua tham số (nơi gọi trong tệp truyền hằng vào vị trí k). Mức nâng lên high.
  - IB giữ 2 TP (khoá field → `keyBytes` → tham số `aes256decrypt/encrypt`). Hết 14/14 FP: Conversations 11, Feeder 3.
  - Recall IB 6/6. Conversations 18,2% → 27,3%, Feeder 36,8% → 43,8%. **Gộp 9 app thật: 36,2% → 41,8% (38/91)**,
    macro 42,8%. → `ket-qua-test/m1_cry-keyhard/`
  - Giới hạn: không theo luồng xuyên tệp (khoá ở lớp Constants dùng ở lớp khác) — phần đó CRY-KEYLIT bắt ở nơi khai báo.

- **2026-10-04 — holdout đợt 5: Aegis 3.4.3 + RedReader 1.26** (luật đóng băng ở `d5bb7a6`; Infinity for Reddit không
  còn trên F-Droid → thay bằng RedReader)
  - Gán nhãn tay 22 cảnh báo → `ground-truth/aegis_labels.json` (0 TP/3), `redreader_labels.json` (7 TP/19, 1 borderline).
  - **Precision holdout 5: Aegis 0%, RedReader 36,8% → gộp 31,8% (7/22); chặt 27,3% (6/22).**
    Chuỗi holdout: đợt 2 5,3% → đợt 3 15,3% → đợt 4 40,0% → đợt 5 31,8%. Gộp 11 app thật: 39,8% (45/113).
  - FP mới lộ ra: WEB-IFACE khớp hàm TỰ VIẾT cùng tên `addJavascriptInterface()` không đối số (5); CRY-IV0 trong bộ
    NHẬP định dạng backup của app khác (Authy, TOTP Authenticator) buộc dùng IV 0 (2). Còn lại: WEB-JS 3, STO-EXT 2
    (người dùng lưu ảnh), CFG-BACKUP 1 (vault đã mã hoá), NET-HTTP 1, WEB-IFACE thật nhưng vô hại 1.
  - TP: RedReader backup token OAuth không mã hoá (adb), cleartext toàn cục, PreviewActivity lọt release (lần 2),
    ảnh tải qua http. → `ket-qua-test/m1_holdout5/`

- **2026-10-04 — M2: điểm tin cậy** (`static_scan.py`: trường `confidence`, `--min-confidence`, cột trong HTML)
  - Mức theo LOẠI BẰNG CHỨNG của luật (bảng `RULE_CONFIDENCE`), không suy từ precision đo được: high = cờ/cấu hình,
    literal, luồng từ hằng; medium = dấu hiệu mạnh nhưng mã có thể có kiểm tra ẩn; low = bề mặt rủi ro.
    CFG-BACKUP: high khi không có quy tắc backup/backupAgent, medium khi có. Phát hiện không đổi trên 12 app.
  - **11 app thật: high 86,4% (19/22); ≥ medium 53,1% (43/81); tất cả 39,8% (45/113)**. Riêng medium 40,7%, low 6,2%.
    Holdout 5 (Aegis, RedReader — app duy nhất chưa dùng chỉnh luật phát hiện): high 1/3, ≥ medium 41,2% (7/17).
  - Recall IB: ≥ medium vẫn 6/6; chỉ high còn 2/6 → ngưỡng khuyến nghị cho báo cáo: **≥ medium**.
  - ⚠️ Lưu ý: (1) 17/22 cảnh báo high là cấu hình mạng/backup — nhóm có quyết định gán nhãn TP gây tranh luận;
    nếu coi là FP thì tầng high sụp. (2) Bảng mức tin cậy được đặt SAU khi đã thấy nhãn 11 app → cần holdout 6
    để kiểm chứng độc lập. (3) CRY-IV0 high sai 2/2 trên Aegis (IV 0 trong bộ nhập định dạng app khác).
    → `ket-qua-test/m2_confidence/`

- **2026-10-04 — holdout đợt 6: KeePassDX 4.5.5 + Breezy Weather 6.2.2** (luật + bảng độ tin cậy đóng băng `226af5a`)
  - KeePassDX: package manifest `com.kunzisoft.keepass.libre` (applicationIdSuffix) chỉ chứa R.java → công cụ mặc định
    chỉ ra 1 cảnh báo (bỏ sót toàn bộ mã). Holdout dùng `--app-pkg com.kunzisoft.keepass`. → LỖI CÔNG CỤ cần sửa:
    suy namespace mã (vd từ `android:name` của <application>/activity), không dùng applicationId.
  - Gán nhãn tay 54 cảnh báo → `keepassdx_labels.json` (1 TP borderline/50), `breezyweather_labels.json` (1 TP/4).
  - **Precision holdout 6: 3,7% (2/54); theo độ tin cậy: high 0/1, ≥ medium 3,8% (2/53) → điểm tin cậy KHÔNG được
    kiểm chứng trên holdout.** Gộp 13 app: high 82,6% (19/23), ≥ medium 33,6% (45/134), tất cả 28,1% (47/167).
  - Nguyên nhân: app quản lý mật khẩu có TỪ VỰNG MIỀN chứa đúng từ khoá (password/token/secret/key) →
    LOG-SENS 34 FP (khớp tên lớp/TAG `MasterCredential`, `PasswordLauncherViewModel`; thông điệp có từ khoá nối với
    giá trị không nhạy cảm), CRY-KEYLIT 13 FP (nhãn trường "Password", "Token", "Private key"). CRY-IV0 (high) khớp
    `ZERO_FIVE` (chữ IV trong FIVE). Breezy: CFG-EXPORT heuristic action nội bộ trên LAUNCHER.
  - Bài học: luật dựa từ khoá có precision phụ thuộc mạnh vào miền của app; điểm tin cậy theo LUẬT không đủ — cần
    tín hiệu theo TỪNG CẢNH BÁO (vd giá trị có dạng bí mật/entropy, biến thật sự giữ dữ liệu nhạy cảm).
    → `ket-qua-test/m2_holdout6/`

- **2026-10-04 — M2: điểm tin cậy THEO TỪNG CẢNH BÁO** (bảng mức theo luật giữ làm mặc định)
  - LOG-SENS: high khi in biến/field/getter có danh từ chính nhạy cảm (`this.password`, `distinctCredentials`);
    medium khi chuỗi KẾT THÚC bằng từ khoá rồi nối giá trị; low khi từ khoá chỉ ở tên lớp/TAG/giữa câu.
    CRY-KEYLIT: high = khoá ngẫu nhiên (≥16 ký tự, entropy ≥3.5, chữ+số) hoặc tiền tố khoá đã biết; low = nhãn chữ,
    snake/UPPER_SNAKE, bảng mã, <8 ký tự; còn lại medium. CRY-IV0: high chỉ khi dùng trong IvParameterSpec/GCM.
    CFG-EXPORT: low khi là LAUNCHER hoặc mã có kiểm tra người gọi. NET-HTTP: low khi new URL("http://") rỗng.
    STO-EXT: medium khi tên tệp dữ liệu/có ghi. WEB-IFACE: low khi hàm tự viết không đối số / chỉ nạp asset.
    CRY-WEAK: low với RSA/ECB.
  - Bỏ quy tắc "component không đọc intent → low": sai nguyên lý (DoTransfer của IB — màn hình đặc quyền mở thẳng được
    là lỗ hổng dù không nhận dữ liệu); phát hiện vì recall IB @≥medium tụt 5/6.
  - **13 app thật: high 88,0% (22/25); ≥ medium 62,9% (44/70); riêng low 3,1% (3/97).** TP bị hạ xuống low: 3/47
    (Nextcloud provider có getCallingUid nhưng kiểm tra thiếu; Conversations media legacy; Feeder Basic Auth dạng
    snake_case). Recall IB @≥medium 6/6, @high 2/6. Holdout 6: ≥ medium 40,0% (2/5).
  - ⚠️ Toàn bộ quy tắc được đặt SAU khi đã thấy nhãn 13 app (kể cả holdout 6) → số trên là tập PHÁT TRIỂN; cần
    holdout 7 (luật + điểm tin cậy đóng băng) để kiểm chứng. → `ket-qua-test/m2_conf_per_alert/`

- **2026-10-04 — holdout đợt 7: Gadgetbridge 0.94.0 + Wikipedia** (luật + điểm tin cậy theo từng cảnh báo đóng băng `9c71644`)
  - Gán nhãn tay 107 cảnh báo → `gadgetbridge_labels.json` (3 TP/100), `wikipedia_labels.json` (0 TP/7).
  - **Holdout 7: tất cả 2,8% (3/107); ≥ medium 7,1% (3/42); high 40,0% (2/5); low 0/65 TP.**
    Gộp 15 app: high 80,0% (24/30), ≥ medium 42,0% (47/112), low 1,9% (3/162), tất cả 18,2% (50/274).
  - Kết luận M2: tầng LOW là bộ lọc nhiễu đáng tin (holdout 6: 0/49 TP, holdout 7: 0/65 TP — bỏ low không mất TP);
    tầng HIGH tương đối ổn (80% trên 15 app); tầng MEDIUM phụ thuộc mạnh miền app → mục tiêu ≥50% ở ≥ medium
    KHÔNG đạt trên holdout (7,1%).
  - FP mới theo miền (Gadgetbridge): mật mã do giao thức thiết bị của hãng (AES/ECB, IV 0, khoá Gree công khai — 3 cái
    ở tầng high), 13 activity cấu hình exported chỉ mở UI, namespace GPX `xmlschemas`. Wikipedia: activity-alias
    LAUNCHER chưa được luật CFG-EXPORT xét.
  - TP: Gadgetbridge `ImageEditActivity` trả ảnh đã giải mã qua setResult (cùng lớp lỗi CanHub cropper).
    → `ket-qua-test/m2_holdout7/`

- **2026-10-04 — viết lại khung Chương 3** theo hướng công cụ `apiscan` (`05_bao-cao/Chuong3_khung.md`); khung cũ ở commit `e34b943`.

- **2026-10-04 — M1: lệnh một bước + tự suy phạm vi mã + bộ test hồi quy**
  - `04_code/scripts/apiscan.py scan app.apk [-o DIR] [--min-confidence medium] [--app-pkg …]`: tính SHA-256,
    tự chạy apktool + JADX (`--no-res`) vào `~/.cache/apiscan/<sha>` (dùng lại lần sau), xuất report.html/json.
    InsecureBankv2: 14 giây từ APK tới báo cáo; 24 cảnh báo, recall 6/6, khớp 24/24 nhãn TP.
  - `infer_app_packages()`: phạm vi = package Manifest (nếu có mã) + namespace lớp Application + namespace
    component (ngoài danh sách thư viện) có LAUNCHER hoặc ≥ 2 component. Sửa KeePassDX (mặc định 1 → 50 cảnh
    báo), K-9 (thêm app.k9mail, net.thunderbird), Nextcloud (thêm com.owncloud → +37 cảnh báo CHƯA gán nhãn).
    Chưa suy được namespace không có component (vd im.conversations.android) → dùng `--app-pkg`.
  - Refactor `analyze()`/`write_reports()`; với `--app-pkg` như cũ kết quả 16/16 app giống hệt trước.
  - `04_code/tests/test_static_scan.py`: 18 nhóm test (~120 ca) từ các tình huống thật + ca tích hợp IB (bỏ qua
    nếu chưa có OUT_IB). Chạy `python3 -m unittest discover -s 04_code/tests -v`. Đã thử làm hỏng luật → test bắt.

- **2026-10-04 — gán nhãn 37 cảnh báo mới của Nextcloud** (phạm vi suy rộng thêm `com.owncloud`, `com.nmc`)
  - Nhãn bổ sung vào `ground-truth/nextcloud_labels.json` (trường `added_on`); kết quả `ket-qua-test/m1_scope/nc.json`.
  - 2 TP mới (đều borderline): cầu nối JS RichDocuments/Collabora (downloadAs, hyperlink…) — nhất quán Jellyfin;
    `GetStatusRemoteOperation` tự rơi https → http khi dò server không có scheme (có cảnh báo UI).
  - **Nextcloud: phạm vi cũ 44,4% (4/9) → phạm vi đúng 13,0% (6/46)**; high 30% (3/10), ≥ medium 20% (5/25).
    → Quét thiếu phạm vi đã thổi phồng precision của Nextcloud; cần ghi vào phần hạn chế/thảo luận.
  - Lớp FP mới: CRY-KEYLIT xếp HIGH cho hằng ĐƯỜNG DẪN API (`/ocs/v2.php/apps/end_to_end_encryption/api/v1/…`,
    6 cảnh báo) vì chuỗi dài có chữ + số; hằng "http://" dùng để so sánh/bỏ tiền tố (6); URL mẫu trong @Preview (3).

- **2026-10-04 — sửa điểm tin cậy CRY-KEYLIT cho đường dẫn/URL**: giá trị bắt đầu bằng `/` hoặc chứa `://` → low
  (thêm 4 ca test, gồm khoá base64 có `/` ở giữa vẫn high). Chỉ 7 cảnh báo đường dẫn API của Nextcloud đổi high →
  low; phát hiện không đổi trên 16 app. Nextcloud (phạm vi đúng): high 30% (3/10) → **100% (3/3)**, ≥ medium 20% →
  27,8% (5/18). Gộp 15 app (Nextcloud phạm vi đúng): high 80,0% (24/30), ≥ medium 39,5% (49/124), low 1,6% (3/187),
  tất cả 16,7% (52/311). Lưu ý: sửa sau khi thấy dữ liệu Nextcloud → tập phát triển. → `ket-qua-test/m2_conf_paths/`

- **2026-10-04 — holdout đợt 8: Briar 1.5.21 + Money Manager Ex 5.5.13** — lần đầu đo bằng `apiscan.py scan`
  (phạm vi tự suy), luật + điểm tin cậy + suy phạm vi đóng băng `d7818bc`.
  - Gán nhãn 16 cảnh báo → `briar_labels.json` (0 TP/5), `mmex_labels.json` (4 TP/11, 1 borderline).
  - **Holdout 8: 25,0% (4/16), chặt 18,8%; high 0/3, ≥ medium 30,8% (4/13), low 0/3 TP.**
    Chuỗi holdout: 18,2 → 5,3 → 15,3 → 40,0 → 31,8 → 3,7 → 2,8 → 25,0%.
  - Tầng high sai 3/3: NET-NSC báo cả khi cleartext chỉ ở domain-config (.onion của Briar, IP 192.168.1.20 sót lại của
    MMEX — lỗi đã thấy ở Tusky nhưng chưa sửa) + khoá CÔNG KHAI Google Play (hex DER) bị CRY-KEYLIT xếp high.
  - TP đáng chú ý (MMEX): ⚠️ hai thành phần exported ([ẩn danh B], [ẩn danh C]). Ẩn danh: lỗ hổng đang được công bố có trách nhiệm cho nhà phát triển; chi tiết sẽ được bổ sung sau khi bản sửa được phát hành. Backup agent sao lưu DB tài chính.
  - Giới hạn suy phạm vi: Briar có mã lõi ở `org.briarproject.bramble`/`org.briarproject.briar` không có component
    → không được quét. → `ket-qua-test/m2_holdout8/`

- **2026-10-04 — sửa NET-NSC/NET-TRUST theo phạm vi network_security_config** (Briar/MMEX từ đây thành tập phát triển)
  - Chỉ đọc tệp Manifest tham chiếu (`android:networkSecurityConfig`); XML parser theo phạm vi: base-config → high;
    domain-config chỉ cảnh báo khi có domain CÔNG KHAI (bỏ .onion, localhost, IP nội bộ, .local…) → medium;
    debug-overrides bỏ qua (chỉ hiệu lực ở bản debug); domain-config lồng nhau kế thừa cleartext. Thêm 7 ca test.
  - Bỏ đúng 3 FP (Tusky .onion, Briar .onion, MMEX 192.168.1.20); giữ mọi TP base-config; luật khác không đổi.
  - **17 app thật (Nextcloud phạm vi đúng): high 80,0% (24/30), ≥ medium 39,6% (53/134), low 1,6% (3/190), tất cả
    17,3% (56/324).** 6 FP high còn lại: mật mã giao thức thiết bị/định dạng app khác (Aegis IV ×2, Gadgetbridge Gree
    khoá + Fossil IV ×2) và khoá CÔNG KHAI Google Play (Briar). → `ket-qua-test/m2_nsc/`

- **2026-10-04 — holdout đợt 9: Termux 0.118.3 + Catima 2.45.1** (`apiscan.py scan`, đóng băng `7135621`)
  - Gán nhãn 7 cảnh báo → `termux_labels.json` (0 TP/3), `catima_labels.json` (1 TP/4).
  - **Holdout 9: 14,3% (1/7); high 1/1, ≥ medium 25,0% (1/4), low 0/3 TP.** Mẫu rất nhỏ (cả hai app sinh ít cảnh báo).
  - Suy phạm vi đúng trên app mới: Catima package `me.hackerchick.catima` → mã `protect.card_locker`.
    Termux `RunCommandService` (chạy lệnh shell cho app khác) có permission riêng → công cụ bỏ qua đúng.
  - Gộp 3 đợt holdout đo bằng điểm tin cậy theo từng cảnh báo (7, 8, 9): ≥ medium 13,6% (8/59); low 0/71 TP.
    → `ket-qua-test/m2_holdout9/`

- **2026-10-04 — viết Chương 3 hoàn chỉnh**: `05_bao-cao/Chuong3.md` (nguồn) → `Chuong3_apiscan.docx` qua
  `05_bao-cao/xuat_docx.py` (Times New Roman 13, giãn 1,5, lề 3/2/2,5 cm như báo cáo đợt 2). 4 hình vẽ bằng
  `05_bao-cao/hinh/ve_hinh_chuong3.py`; 9 bảng. Số liệu cuối: `ket-qua-test/final/summary.txt` (19 app, 331 cảnh báo,
  57 TP; high 80,6%, ≥ medium 39,1%, low 1,6%; nhạy cấu hình mạng→FP: high 9,7%). Hai phát hiện cần công bố có
  trách nhiệm được ẩn danh. Lưu ý: KHÔNG đặt tên `Chuong3.docx` (trùng `chuong3.docx` cũ trên macOS không phân biệt hoa
  thường).

- **2026-10-04 — đối chứng MobSF trên cùng bộ nhãn** (MobSF v4.5.4 Docker ARM64, cấu hình mặc định, chỉ tĩnh)
  - `04_code/scripts/mobsf_batch.py` (REST upload→scan→report_json, bỏ trường `strings`) → `ket-qua-test/mobsf/` (19 app
    + IB). Lỗi gặp: `re_scan=1` với app chưa quét → MobSF chỉ "update" bản ghi không tồn tại → "Report not Found"; nay
    mặc định `re_scan=0`. MobSF mặc định bỏ qua mã IB vì `SKIP_CLASS_PATH` chứa `com/android/` (không phải do semgrep).
  - `04_code/scripts/compare_mobsf.py summary|sample|eval`; nhãn mẫu 100/1.182 (seed 42) →
    `ground-truth/mobsf_sample_labels.json`.
  - **IB: apiscan 6/6, MobSF mặc định 2/6, bỏ `com/android/` 3/6 + V05 một phần. App thật: MobSF 1.182 cảnh báo
    high/warning (apiscan 331); precision MobSF 5,0% (KTC 2,2–11,2%) vs apiscan 17,2% (13,5–21,7%); phần mã MobSF 1,3%;
    MobSF phủ 41/57 TP của apiscan (thiếu NET-HTTP 9, WEB-IFACE 5, LOG-SENS 2).** MobSF tìm 1 TP apiscan bỏ sót (MMEX
    CSDL ở bộ nhớ ngoài, mã R8 dời vào `defpackage`). → `ket-qua-test/doi_chung_mobsf.md`, `mobsf/summary.txt`
  - Chương 3 mục 3.5 viết lại (Bảng 3.10), cập nhật 3.6/3.7, xuất lại `Chuong3_apiscan.docx`.
  - Lưu ý máy: Docker + MobSF đẩy swap lên 12–14 GB, ổ còn ~3 GB khi chạy xong — tắt container khi không dùng.

- **2026-10-04 — viết Kết luận và ghép luận văn hoàn chỉnh**
  - `05_bao-cao/KetLuan.md`: kết quả đạt được (theo 5 mục tiêu đề cương), hạn chế (gồm cả phần benchmark động ở
    Chương 2 chưa chạy, pipeline mới có phần MobSF), hướng phát triển.
  - `05_bao-cao/ghep_luan_van.py` → `DoAnTotNghiep_NguyenDucTam.docx`: bìa + phần đầu + Chương 1 (Báo cáo đợt 1),
    Chương 2 + Phụ lục A–D (Báo cáo đợt 2), Chương 3, Kết luận, Tài liệu tham khảo hợp nhất 28 mục (trích dẫn Chương 2
    đánh số lại, thêm [22]–[28]; Chương 3 thêm 8 trích dẫn). Danh mục ký hiệu/hình/bảng gộp cả 3 chương; viết lại Lời
    cảm ơn, Lời nói đầu cho toàn luận văn; câu mô tả pipeline ở 2.5.4 sửa cho khớp thực tế (chỉ có `mobsf_batch.py`).
  - Cần làm trong Word: mở file → "Yes" cập nhật trường để mục lục có số trang; rà ngắt trang.

- **2026-10-04 — báo cáo chuyên đề cơ sở + sửa luận văn**
  - `05_bao-cao/chuyen-de-co-so/`: báo cáo chuyên đề cơ sở chuyên ngành (tên trùng tên đồ án, nên hỏi GVHD), 3 chương +
    thực nghiệm InsecureBankv2, thí nghiệm tìm mẫu mới (`thuc_nghiem_tim_mau.py` → `ket_qua_tim_mau.txt`).
  - Sửa Báo cáo đợt 1: Ranganath & Mitra là 14 công cụ GỘP phát hiện 30/42 lỗ hổng (~71%), không phải "khoảng 30%".
  - Luận văn ghép, Chương 3 riêng và chuyên đề chuyển sang khổ A4; bảng rộng hơn 16 cm được co theo tỉ lệ.

- **2026-11-08 — slide bảo vệ, batch, YAML/suppression, quét động, ghép lại luận văn**
  - Slide bảo vệ 16 trang (Artifact Slides, link trong `06_slide/README.md`): vấn đề → RQ → thiết kế → kết quả → MobSF →
    hạn chế → kết luận; mọi số lấy từ Chương 3 / `final/summary.txt`, ghi chú người nói ở từng slide.
  - `apiscan.py batch` → `03_benchmark/ket-qua-test/batch_20apk/` (index.html, summary.csv/json, báo cáo từng app).
    Chạy lại 20 APK: **331 cảnh báo trên 19 app thật, khớp từng app với `final/summary.txt`**, kể cả 4 app (MMEX, Termux,
    Catima, Briar) giải nén + JADX lại từ đầu. Thời gian phân tích lần này cao hơn bảng 3.4.7 (vd Gadgetbridge 15,3 s vs
    6,9 s) vì đọc mã từ ổ SSD ngoài — không dùng làm số đo tốc độ.
  - `apiscan_config.py`: YAML `min_confidence`/`app_pkg`/`rules.disable`/`suppress` (id dấu vân tay 12 ký tự bỏ số dòng,
    rule, glob location/evidence, bắt buộc `reason`); khoá gõ sai → lỗi. Báo cáo liệt kê cảnh báo đã bỏ qua + lý do, cảnh
    báo mục suppress không khớp. `apiscan.py baseline report.json` sinh YAML bỏ qua mọi cảnh báo hiện có. Thử trên
    KeePassDX: baseline 50/50 bị bỏ qua; cấu hình mẫu: 2 hiện + 47 ẩn (≥ medium) + 1 luật tắt = 50.
  - `dynamic_scan.py` + `apiscan.py dynamic` thay `pipeline.py` đã mất: cổng an toàn (chỉ loopback/mạng riêng, hoặc
    `--authorization <tệp>` ghi SHA-256), chỉ gửi ZAP endpoint cùng host, accessUrl + yêu cầu mẫu → spider → ascan →
    gộp theo (plugin, path, param), CWE → OWASP API 2023, gộp MobSF (high/warning trong phạm vi). Test với ZAP giả lập.
    **Chưa chạy ZAP thật**: image `zaproxy/zap-stable` đã kéo về colima; backend AndroLabServer (Python 2) cần người
    dùng tự dựng — lần này không chạy mã backend tải từ ngoài. Yêu cầu mẫu: `04_code/dynamic/ib_seed_requests.txt`.
  - Test: 19 → 37 ca (`test_config_batch.py`, `test_dynamic.py`), tất cả qua.
  - Luận văn: Chương 3 mục 3.2.6 thêm batch/YAML/dynamic, 3.4.7 thêm lần chạy batch; Kết luận chuyển batch + YAML từ
    "hướng phát triển" sang "đạt được", hạn chế ghi rõ phần động chưa có số liệu. Ghép lại `DoAnTotNghiep_NguyenDucTam.docx`
    (venv có python-docx, docxcompose) và xuất `Chuong3_apiscan.docx`. Máy không có Word/LibreOffice → xuất
    `DoAnTotNghiep_NguyenDucTam.pdf` bằng Gotenberg (LibreOffice trong Docker, updateIndexes) để có mục lục điền số trang:
    102 trang; dò tự động không thấy tiêu đề mồ côi ở thân bài, chỉ có bảng ký hiệu tràn 4 dòng sang trang 7.

- **2026-11-08 (chiều) — recall trên lỗ hổng đã công bố, bộ đo đồng thuận gán nhãn**
  - `03_benchmark/recall_cve/`: 10 lỗ hổng GitHub Security Lab trên 5 app F-Droid (Nextcloud, ownCloud, Nextcloud News,
    Wikipedia, OsmAnd), APK bản bị ảnh hưởng từ F-Droid archive (SHA-256 khớp chỉ mục), luật đóng băng, tiêu chí
    `TIEU_CHI.md` ghi trước khi quét. **Đúng cơ chế 3/10 (≥ medium 2/10), chỉ đúng thành phần 7/10, bỏ sót 0/10.**
    Sai lệch tiêu chí: CVE-2021-41166 chấm trên Nextcloud 3.17.0 vì 3.18.0 đã sửa. Hai quy tắc cần xét lại (phân tích
    sau kết quả): hạ low khi có gọi API kiểm tra bên gọi (làm mất CVE-2021-43863 ở ≥ medium); service + action tuỳ biến +
    không permission bị xếp bề mặt (CVE-2026-65995) — nâng thành cảnh báo chỉ thêm 6 cảnh báo / 19 app.
  - `04_code/scripts/dong_thuan.py` + `03_benchmark/ground-truth/dong_thuan/`: phiếu 80 cảnh báo (30 TP + 50 FP gốc, seed
    42, 69 mục kèm đoạn mã), `HUONG_DAN.md`, `dap_an_an.json` (KHÔNG đưa người gán 2), lệnh `score` tính đồng ý, Cohen's
    kappa + bootstrap. Chưa có người gán thứ hai.
  - Quét động: `04_code/dynamic/backend/` (Dockerfile Python 2.7 cho AndroLabServer, ZAP chung network namespace). Chờ người
    dùng tự dựng backend.
  - Luận văn: thêm mục 3.6 (Bảng 3.11), 3.6→3.7, 3.7→3.8; TLTK [29] GitHub Security Lab, [30] Cohen 1960; Kết luận cập
    nhật. PDF 105 trang. Slide thêm trang "Recall trên 10 lỗ hổng đã công bố" (17 trang).

- **2026-11-08 (tối) — quét động thật trên InsecureBankv2**
  - Backend AndroLabServer trong container `ib-backend` (127.0.0.1:8888), ZAP 2.17.0 chung network namespace; mỗi cấu
    hình chạy trên container mới. → `03_benchmark/ket-qua-test/dynamic_ib/KET_QUA.md`
  - A chỉ URL gốc: 3 cảnh báo, 0 endpoint API. B + bản đồ endpoint (GET): 9, 0 high. C + 5 POST có tham số từ mã dịch
    ngược: 27, 2 high = **XSS phản xạ /login, /devlogin (username)** — ngoài đáp án, xác minh tay (`text/html`).
  - ZAP không tự thấy lỗi nghiệp vụ; kiểm chứng thủ công theo bản đồ: **V07, V08 (BOLA), V09 (đổi mật khẩu không xác thực +
    dò tên người dùng), V12 (mật khẩu 1 ký tự) đều xác nhận.**
  - Luận văn: mục 3.7 mới (Bảng 3.12), 3.8 thảo luận, 3.9 kết luận; PDF 107 trang. Slide thêm trang quét động (18 trang).
  - Lưu ý: khởi động lại `ib-backend` làm container `zap` (network container:ib-backend) mất mạng → tạo lại cả hai.

- **2026-11-08 (đêm) — chuẩn bị bảo vệ**
  - `06_slide/HOI_DAP.md`: 16 câu hội đồng dễ hỏi, mỗi câu trả lời ngắn + bổ sung + tệp minh chứng; số lấy từ Chương 3.
  - Ma trận `test_case_matrix_da_dien.xlsx` (sheet Tiêu chí): điền MobSF (2/6 mục tĩnh, precision 5,0% mẫu 100, 84 s/app)
    và ZAP (0/4 mục phía máy chủ, 2 high XSS đúng, 27 cảnh báo); ô chưa đo để trống, Burp/Frida chưa chạy.

- **2026-11-08 (khuya) — tự trích tham số endpoint cho quét động**
  - `04_code/scripts/request_extract.py`: HttpClient (`new HttpPost(..."/path")` + `BasicNameValuePair`) và Retrofit
    (`@POST/@GET...` + `@Field/@Query/@Path/@Header/@Part/@Body`) → `report.json["requests"]` + bảng trong report.html.
    `endpoints` giữ nguyên. `apiscan dynamic` tự sinh yêu cầu mẫu (giá trị giả), `--seed-requests` thay mục cùng
    phương thức + đường dẫn, `--no-auto-requests` để tắt.
  - IB: 5/5 yêu cầu khớp tệp viết tay. ZAP thật, cấu hình D (chỉ tự trích): 26 cảnh báo, 2 high = cùng XSS như C, 123 s.
    16 app: số cảnh báo không đổi; có yêu cầu ở IB 5, Wikipedia 33, Conversations 2; Tusky 0 do R8.
    → `03_benchmark/ket-qua-test/dynamic_ib/KET_QUA.md` mục 3, `tu_trich/`.
  - Test 37 → 48 ca (`test_request_extract.py`).
  - Luận văn: 3.2.6 thêm bộ trích yêu cầu, 3.7 Bảng 3.12 thêm cấu hình D + đoạn phân tích, 3.9 và Kết luận cập nhật;
    `xuat_docx.py` đặt cantSplit cho dòng bảng (Bảng 3.12 bị cắt ngang dòng). PDF 108 trang. Slide quét động thêm dòng D.
- **2026-11-10 — holdout đợt 10: đo bộ luật CFG-EXPORT v2** (đóng băng `9fa79f2`, tiêu chí `0a96461`)
  - Organic Maps 2026.09.29, Etar 1.0.57, FlorisBoard 0.5.2, OpenTracks 4.29.0; 19 nhãn (`b4be4d0`).
  - v1: 11,8% (2/17), chặt 5,9%, ≥ medium 15,4% (2/13); tầng low 0/4. v2: 10,5% (2/19), ≥ medium 13,3%.
  - Thay đổi 1 (không hạ low vì "có gọi" API kiểm tra bên gọi): 0 cảnh báo. Thay đổi 2 (service + action tuỳ biến):
    2 cảnh báo, 0 TP (CarAppService, Health Connect — có xác thực bên gọi). Cả hai: chưa kết luận được.
  - Tham khảo: v1 trên 19 app tái lập đúng 331 / 17,2% / ≥ medium 39,1%. v2: thay đổi 1 nâng 2 cảnh báo (1 TP Nextcloud
    FileContentProvider, 1 FP K-9); thay đổi 2 thêm 6 cảnh báo chưa nhãn, đều service thư viện (Media3 ×3, UnifiedPush ×2,
    Health Connect). CVE: recall đúng cơ chế 3/10 → 4/10 (43863 lên medium, 65995 thành cảnh báo).
  - Giữ v1 mặc định; hướng sửa chưa đo: không coi action namespace thư viện là tuỳ biến.
    → `03_benchmark/ket-qua-test/m3_holdout10/KET_QUA.md`, `cham.py`, `tham_khao/` (`274f6a4`).
  - Luận văn: Bảng 3.4, 3.6 thêm đợt 10; 3.3.4, cuối 3.6, 3.4.4, 3.9, Kết luận; Hình 3.3 thêm đợt 10; 608 nhãn / 23 app.
    PDF 109 trang. HOI_DAP câu 1, 4, 5, 10.
  - Kiểm tra lại 2 lỗ hổng báo riêng trên bản F-Droid mới nhất: chưa sửa. HOI_DAP câu 16.
- **2026-11-10 — M5: đóng gói, tài liệu, demo**
  - `04_code/pyproject.toml`: `pip install 04_code` (tuỳ chọn `[config]` kèm PyYAML) → lệnh `apiscan`, `--version` 1.0.0;
    cài thử trong venv sạch, chạy được từ thư mục bất kỳ.
  - `04_code/README.md`: cài đặt, 4 lệnh, cấu hình/suppression, cổng an toàn quét động, mã thoát (0/1/2 đã kiểm), đọc
    báo cáo, bộ luật, giới hạn.
  - Demo `06_slide/demo/`: `DEMO.md` (kịch bản 3 phút + xử lý sự cố), `demo.sh` (`--cold`, `--newpipe`, `--offline`),
    báo cáo chạy sẵn ≥ medium. Đo: InsecureBankv2 lần đầu 13–19 s (22 cảnh báo, recall 6/6, 6 endpoint, 5 yêu cầu),
    có cache 0,2 s; NewPipe lần đầu 25–45 s (1 cảnh báo, 145 endpoint). Test 50/50.

## Việc tiếp theo (chi tiết ở ROADMAP_TOOL.md)

- [x] Trao đổi GVHD — thầy Phạm Duy Trung đã cho phép đổi trọng tâm sang xây công cụ `apiscan` (sinh viên xác nhận ngày 2026-10-04).
- [x] Cập nhật đề cương `de_cuong_DA.docx` theo hướng công cụ (commit cf8da06).
- [x] M1: CLI `apiscan` + lọc 4 loại FP, giữ recall 100% InsecureBankv2, đo lại precision NewPipe.
- [x] M3: batch + dashboard (2026-11-08).
- [x] M4: chạy `apiscan dynamic` với ZAP thật trên backend InsecureBankv2 (2026-11-08).
- [x] Tự trích phương thức + tham số endpoint từ mã (HttpClient, Retrofit) → yêu cầu mẫu cho ZAP (2026-11-08). Còn: OkHttp builder; Burp/Frida.
- [ ] Tìm người gán nhãn thứ hai → `dong_thuan.py score`.
- [x] Holdout đợt 10 đo 2 quy tắc CFG-EXPORT rút ra từ phép đo recall (2026-11-10): chưa kết luận được (< 3 cảnh báo bị tác động), giữ v1 mặc định.
- [x] Mục lục `.docx` điền sẵn số trang từ bookmark PDF (`05_bao-cao/dien_muc_luc.py`, 2026-11-10); Word vẫn tự cập nhật khi mở.

## Mẫu dòng cập nhật (copy khi ghi mới)

- **YYYY-MM-DD**
  - <việc đã làm> → <đo được gì> → <file minh chứng>
