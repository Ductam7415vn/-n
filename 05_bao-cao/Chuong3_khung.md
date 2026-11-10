# CHƯƠNG 3. XÂY DỰNG VÀ ĐÁNH GIÁ CÔNG CỤ PHÁT HIỆN LỖ HỔNG TĨNH `apiscan`

> **Khung nội dung — cập nhật 2026-10-04.** Mọi con số trong khung đều lấy từ lần chạy thật, kèm đường dẫn
> file minh chứng trong repo. Ký hiệu: ✅ đã có số liệu · ⏳ cần bổ sung · ❓ cần quyết định trước khi viết.
> Khung cũ (hướng benchmark 7 công cụ + `pipeline.py`) được giữ trong git, commit `e34b943`.

---

## Việc cần chốt TRƯỚC khi viết

| # | Việc | Ảnh hưởng |
|---|---|---|
| ✅1 | Thầy Phạm Duy Trung **đã cho phép** đổi trọng tâm (xác nhận 2026-10-04). Còn: cập nhật đề cương `de_cuong_DA.docx` cho khớp | Toàn bộ cấu trúc chương |
| ❓2 | **Chính sách gán nhãn nhóm cấu hình mạng/backup** (cleartext toàn cục, tin CA người dùng, allowBackup): TP hay FP? Hiện gán TP nhất quán | Gần như toàn bộ tầng tin cậy *high* (mục 3.4.4) |
| ❓3 | **Duyệt 9 nhãn `borderline`** (Jellyfin ×4, Feeder ×2, Conversations, RedReader, KeePassDX) | Số "chặt" ở 3.4.3 |
| ❓4 | **Công bố có trách nhiệm** phát hiện ở một thư viện xác thực chứng chỉ (3.4.6) trước khi đưa chi tiết vào luận văn/slide | Đạo đức, nội dung 3.4.6 |
| ⏳5 | `pipeline.py` (MobSF + ZAP) **không còn trên máy** → phần động chỉ còn là hướng phát triển, trừ khi tìm lại được | Mục 3.5, 3.6 |
| ⏳6 | Một người gán nhãn → nên nhờ thêm 1 người gán lại một mẫu (vd 50 cảnh báo) để đo độ đồng thuận (Cohen's κ) | Độ tin cậy số liệu |

---

## 3.1. Bối cảnh và mục tiêu của chương

- Nhắc lại khoảng trống từ Chương 1–2: công cụ sẵn có (MobSF, JADX…) cho **nhiều cảnh báo nhưng ít cảnh báo
  dùng được** trên app thật; người kiểm tra phải lọc tay.
- Kết quả khởi điểm (M0) làm động lực: cùng một bộ luật tĩnh đạt precision 100% trên app có chủ đích
  (InsecureBankv2) nhưng chỉ **5,3% (1/19)** trên app thật NewPipe. ✅ `03_benchmark/ket-qua-test/m0_baseline/`
- Mục tiêu đo được của công cụ (giữ nguyên như đặt ra từ đầu, không chỉnh sau khi có kết quả):
  1. Recall **100%** trên 6 lỗ hổng tĩnh của đáp án InsecureBankv2.
  2. Precision **≥ 50%** trên app thật **chưa dùng để chỉnh luật** (holdout).
  3. Đầu ra dùng được: báo cáo HTML/JSON gắn nhãn OWASP, bản đồ endpoint, điểm tin cậy.
- Câu hỏi nghiên cứu của chương (đề xuất):
  - RQ1: Các kỹ thuật giảm báo nhầm dựa trên ngữ cảnh có giữ được recall không?
  - RQ2: Precision đo trên tập phát triển phản ánh đúng precision trên app mới đến đâu?
  - RQ3: Điểm tin cậy theo từng cảnh báo có giúp người kiểm tra lọc nhiễu mà không mất lỗ hổng thật không?

---

## 3.2. Thiết kế công cụ

### 3.2.1. Kiến trúc tổng thể ✅

- Sơ đồ ⏳ [vẽ]: `APK → apktool (Manifest, res) + JADX (Java) → 3 bộ phân tích (Manifest · network_security_config ·
  mã nguồn) → danh sách cảnh báo + bề mặt tiếp nhận intent + bản đồ endpoint → chấm điểm tin cậy → JSON + HTML`.
- Nguyên tắc: **chỉ đọc tệp**, không cài/chạy app, không gửi request tới máy chủ (phù hợp ràng buộc đạo đức ở 1.x).
- Mã nguồn: `04_code/scripts/static_scan.py` (888 dòng), kiểm thử `04_code/scripts/test_groundtruth.py` (203 dòng).
- Hạn chế hiện tại cần nêu: apktool/JADX vẫn chạy tay trước (chưa có lệnh `apiscan scan app.apk` một bước — M1 còn dở).

### 3.2.2. Bộ luật và ánh xạ OWASP Mobile Top 10 – 2024 ✅

Bảng 3.x — 20 luật (gom theo OWASP):

| Nhóm OWASP | Luật | Phát hiện gì | Mức tin cậy mặc định |
|---|---|---|---|
| M1 Credential | CRY-KEYLIT, CRY-KEYHARD, KEY-SERVICE | Bí mật viết cứng; khoá AES/HMAC truy về hằng; chuỗi giống API key | theo giá trị / high / low |
| M4 I/O Validation | WEB-JS, WEB-IFACE | WebView bật JS; cầu nối JS ↔ native | low / medium |
| M5 Communication | NET-CLEAR, NET-NSC, NET-TRUST, NET-SDK, NET-HTTP | Cleartext toàn cục; tin CA người dùng; targetSdk < 28; URL http khi kết nối | high … medium |
| M8 Misconfiguration | CFG-DEBUG, CFG-BACKUP, CFG-EXPORT, API-HIDDEN | debuggable; allowBackup; component exported không bảo vệ; endpoint dev/test | high / theo quy tắc backup / medium |
| M9 Data Storage | STO-EXT, STO-PREF-WORLD, LOG-SENS | Tạo tệp ở bộ nhớ ngoài; SharedPreferences world-readable; log giá trị nhạy cảm | low / high / theo tín hiệu |
| M10 Cryptography | CRY-WEAK, CRY-IV0, CRY-HASH | ECB/DES/RC4; IV tĩnh; MD5/SHA-1 | medium / high / low |

### 3.2.3. Các kỹ thuật giảm báo nhầm (đóng góp kỹ thuật chính) ✅

Mỗi kỹ thuật: nêu **lớp báo nhầm** gặp ở app thật → **ý tưởng** → **ví dụ trước/sau** (trích tệp:dòng) → **ràng buộc
không mất TP** (dẫn ví dụ InsecureBankv2 vẫn bắt được).

1. **NET-HTTP theo ngữ cảnh literal** (thay danh sách domain): bỏ URI namespace/feature (đối số của
   `findChild`, `setFeature`…), URI kiểu đặc tả (`#`, `/protocol/`, `.dtd`), link mở trình duyệt, mã chuẩn hoá
   `http→https`; giữ hạ cấp `replace("https://","http://")`. Ví dụ: Conversations 42 → 0 FP. Commit `3fd2ccb`.
2. **CFG-EXPORT tách "cảnh báo" và "bề mặt tiếp nhận intent"**: XML parser; tính exported ngầm định
   (targetSdk < 31); cảnh báo khi không có intent-filter hoặc nhận action **do chính app tự gửi**; còn lại đưa vào
   mục bề mặt. Ví dụ: `MyBroadCastReceiver` (IB) vẫn bắt nhờ `setAction("theBroadcast")`. Commit `6fd7d3b`.
3. **LOG-SENS chỉ khi log GIÁ TRỊ** (biến/field nhạy cảm hoặc từ khoá nối với giá trị), tách đối số bằng khớp
   ngoặc. K-9: 9 → 0 FP. Commit `ef6b544`.
4. **STO-EXT chỉ khi ghép thư mục ngoài với tên tệp** (app tự tạo tệp ở vùng dùng chung). Commit `a84dc9e`.
5. **CRY-KEYLIT phân biệt tên khoá và bí mật** (SQL, tên đủ package, `KEY_*/PREF_*`, trùng từ với tên biến) và
   quét thêm `BuildConfig`. AntennaPod: 110 → 0 FP; bắt thêm API key PodcastIndex (FN trước đó). Commit `19f2943`.
6. **CRY-KEYHARD bằng phân tích luồng trong tệp**: lan truyền hằng qua phép gán (theo phạm vi hàm) và qua
   tham số; IB: `key` (field) → `keyBytes` → tham số `aes256decrypt()`. Conversations 11 → 0 FP. Commit `d5bb7a6`.

> Gợi ý trình bày: một bảng "lớp FP → kỹ thuật → số FP trước/sau → TP giữ lại", số liệu ở `docs/PROGRESS.md`.

### 3.2.4. Điểm tin cậy theo từng cảnh báo ✅

- Phân biệt **severity** (mức nguy hiểm nếu đúng) và **confidence** (độ chắc chắn bằng chứng đúng).
- Quy tắc theo tín hiệu của từng cảnh báo (bảng 3.x): ví dụ LOG-SENS high khi in biến có danh từ chính là
  password/token/credentials; CRY-KEYLIT high khi giá trị có entropy cao/tiền tố khoá đã biết; CRY-IV0 high chỉ
  khi mảng thực sự vào `IvParameterSpec`; CFG-EXPORT low khi component là LAUNCHER hoặc có kiểm tra người gọi.
- Nêu một quy tắc đã **loại bỏ vì sai nguyên lý**: "component không đọc intent → low" (DoTransfer của IB là màn
  hình đặc quyền mở thẳng được — lỗ hổng dù không nhận dữ liệu). Bài học: kiểm tra quy tắc với đáp án trước.
- CLI: `--min-confidence {low,medium,high}`. Commit `226af5a`, `9c71644`.

### 3.2.5. Đầu ra của công cụ ✅ / ⏳ ảnh chụp

- JSON (`issues`, `attack_surface`, `endpoints`, `meta`), HTML (nhóm theo OWASP, cột mức/tin cậy, bằng chứng
  tệp:dòng, bảng bề mặt intent, bản đồ endpoint).
- ⏳ Chèn ảnh chụp báo cáo HTML của InsecureBankv2 và một app thật (vd `ket-qua-test/m2_holdout7/wp.html`).

---

## 3.3. Phương pháp đánh giá

### 3.3.1. Bộ đáp án InsecureBankv2 ✅

- APK SHA-256 `b18af2a0…94a4`. Đáp án V01–V12 (Bảng 2.10); **6 mục thuộc phạm vi tĩnh**: V01, V02, V05, V06,
  V07, V11. Điều kiện chấm chặt (V06 phải đủ cả 6 component; V02 đủ 3 tệp + targetSdk).
- **Đính chính đáp án** ✅ (đã sửa trong Báo cáo đợt 2, commit `a85ec73`). Đoạn văn dùng được cho luận văn:

  > Trước khi chạy thực nghiệm, đáp án V01–V12 ở Bảng 2.10 được đối chiếu lại với hai nguồn sự thật: mã dịch ngược
  > của ứng dụng bằng JADX và mã nguồn công khai của máy chủ đi kèm (`AndroLabServer/app.py`). Việc đối chiếu cho
  > thấy mô tả của bốn mục và một phần Bảng 2.7 không khớp với mã thật, và các mục này đã được hiệu chỉnh theo mã
  > nguồn (Bảng 3.x). Nhóm OWASP của cả bốn mục giữ nguyên. Sáu mục tĩnh dùng để đo recall (V01, V02, V05, V06,
  > V07, V11) chỉ có V05 thay đổi phần mô tả, và vẫn thuộc M10, vẫn phát hiện được bằng phân tích tĩnh; các mục còn
  > lại (V04, V08, V09) thuộc nhánh động, không tham gia phép đo của chương này. Vì vậy các số liệu recall ở mục 3.4.1
  > không bị ảnh hưởng. Sai sót trong tài liệu đáp án — vốn được coi là chuẩn — cho thấy đáp án cũng cần được kiểm
  > chứng bằng mã nguồn trước khi dùng để chấm công cụ.

  Bảng 3.x — Hiệu chỉnh đáp án InsecureBankv2:

  | Mục | Mô tả ban đầu (Chương 2) | Mô tả sau đối chiếu mã nguồn | Bằng chứng |
  |---|---|---|---|
  | V04 (M9) | Tên đăng nhập và mật khẩu lưu dạng rõ trong SharedPreferences | Tên đăng nhập mã hoá Base64, mật khẩu mã hoá AES bằng khoá viết cứng — giải mã ngược được | `DoLogin.java:144-148` |
  | V05 (M10) | Dùng DES khoá 56 bit | AES/CBC với khoá viết cứng và IV tĩnh toàn số 0 | `CryptoClass.java:22-23` |
  | V08 (API1) | Đổi tham số định danh để xem giao dịch của người khác | `/dotransfer` nhận `from_acc` tuỳ ý → chuyển tiền từ tài khoản của người khác | `app.py`, hàm `dotransfer` |
  | V09 (M3, API2) | Mã thông báo không được kiểm tra, phiên không hết hạn | Không có cơ chế phiên; `/changepassword` không xác thực; phản hồi `/login` cho phép dò tên người dùng | `app.py`, hàm `login`, `changepassword` |
  | Bảng 2.7 | Có điểm cuối `/getusers` (API5); `/getaccounts` lộ dữ liệu thừa (API3) | Máy chủ chỉ có 5 điểm cuối, không có `/getusers`; `/getaccounts` chỉ trả số tài khoản — rủi ro thật là gửi lại thông tin đăng nhập ở mọi yêu cầu (API2) | `app.py` (5 route) |

  ⏳ Hình 2.2 và 2.6 (ảnh) cần vẽ lại nếu có thể hiện token/phiên hoặc `/getusers`.

### 3.3.2. Tập ứng dụng thật ✅

15 ứng dụng mã nguồn mở tải từ F-Droid (hợp pháp để phân tích tĩnh), SHA-256 đầy đủ ở
`04_code/target-app/APK_SOURCES.md`. Bảng 3.x:

| Vai trò | Ứng dụng (phiên bản) | Loại | Số cảnh báo đã gán nhãn |
|---|---|---|---|
| Phát triển (M0) | NewPipe 0.29.1 | Video | 20 |
| Holdout đợt 1 | Tusky 32.2 · K-9 Mail 23.1 | Mạng xã hội · Email | 6 · 16 |
| Holdout đợt 2 | AntennaPod 3.12.2 · Nextcloud 35.0.0 | Podcast · Đồng bộ tệp | 130 · 40 |
| Holdout đợt 3 | Conversations 2.20.4 · Jellyfin 2.7.3 | Chat XMPP · Media server | 75 · 10 |
| Holdout đợt 4 | DAVx⁵ 4.5.20 · Feeder 2.23.2 | CalDAV/CardDAV · RSS | 6 · 19 |
| Holdout đợt 5 | Aegis 3.4.3 · RedReader 1.26 | 2FA · Reddit | 3 · 19 |
| Holdout đợt 6 | KeePassDX 4.5.5 · Breezy Weather 6.2.2 | Mật khẩu · Thời tiết | 50 · 4 |
| Holdout đợt 7 | Gadgetbridge 0.94.0 · Wikipedia r/50606 | Thiết bị đeo · Tri thức | 100 · 7 |

Tổng **529 dòng nhãn** (kể cả 24 của InsecureBankv2) ở `03_benchmark/ground-truth/*_labels.json`.

### 3.3.3. Quy trình gán nhãn ✅

- Mỗi cảnh báo đối chiếu với mã dịch ngược / manifest / tệp cấu hình; ghi `reason`.
- **TP** = chỉ đúng một điểm yếu có thật. **FP** chia `pattern` (khớp mẫu sai) và `intended` (hành vi cố ý/bắt buộc).
  `borderline` = nhận định có thể tranh luận → báo thêm số "chặt" (coi borderline là FP).
- Quy ước nhất quán xuyên app (vd mật mã do giao thức quy định → FP `intended`: CRAM-MD5/APOP, AES-ECB của
  thiết bị đeo; cleartext/tin CA người dùng toàn cục → TP — ❓2).
- Ghi nhận FN đã biết (`known_false_negatives`), vd secret PodcastIndex truyền thẳng vào `sha1(...)`.
- Hạn chế: một người gán nhãn (⏳6).

### 3.3.4. Giao thức holdout ✅

- Trước mỗi đợt: **đóng băng** luật (ghi commit), chạy trên 2 app mới, gán nhãn, đo — **không sửa luật** dựa trên
  app đó trong cùng đợt. Sau khi sửa luật, app đó chuyển thành tập phát triển và cần đợt holdout mới.
- Lý do: chống "học vẹt" — precision trên app đã dùng để chỉnh luật bị thổi phồng (chứng minh ở 3.4.3).

### 3.3.5. Chỉ số ✅

Recall tĩnh trên IB; precision = TP/(TP+FP) theo nhãn (micro gộp, macro theo app); precision chặt; precision theo
tầng tin cậy (riêng tầng và cộng dồn ≥ mức); tỉ lệ giảm số cảnh báo khi lọc; số TP bị mất khi lọc.

---

## 3.4. Kết quả

### 3.4.1. Recall trên InsecureBankv2 (RQ1) ✅

- **6/6 mục tĩnh** ở mọi phiên bản luật (M0 → 9c71644); precision 24/24; bắt thêm V04, V10 (đáp án xếp "động").
- Theo ngưỡng tin cậy: ≥ medium vẫn **6/6**; chỉ high còn 2/6.
- Giới hạn: V03 (thiếu certificate pinning) là lỗi "vắng mặt" — không bắt được bằng dấu hiệu tĩnh.
- Minh chứng: `ket-qua-test/*/test_output*.txt` (mọi lần chạy đều `PASS`).

### 3.4.2. Precision trên tập phát triển ✅

Bảng 3.x — NewPipe qua từng cải tiến (cùng một APK):

| Phiên bản luật | Cảnh báo | TP | Precision |
|---|---|---|---|
| M0 (baseline) | 19 | 1 | 5,3% |
| + NET-HTTP | 13 | 1 | 7,7% |
| + CFG-EXPORT | 7 | 1 | 14,3% |
| + LOG-SENS | 6 | 1 | 16,7% |
| + STO-EXT | 3 | 1 | 33,3% |

Gộp các app phát triển tại từng thời điểm: 35,7% (3 app) → 34,9% (5 app) → 35,0% (7 app) → 41,8% (9 app).
Minh chứng: `ket-qua-test/m1_*`.

### 3.4.3. Precision trên holdout (RQ2) — kết quả chính ✅

Bảng 3.x — mỗi đợt đo **trước** khi sửa luật dựa trên đợt đó:

| Đợt | Ứng dụng | Luật đóng băng | Cảnh báo | TP | Precision | Chặt |
|---|---|---|---|---|---|---|
| 1 | Tusky, K-9 Mail | `6fd7d3b` | 22 | 4 | 18,2% | 18,2% |
| 2 | AntennaPod, Nextcloud | `a84dc9e` | 169 | 9 | 5,3% | 5,3% |
| 3 | Conversations, Jellyfin | `19f2943` | 85 | 13 | 15,3% | 9,4% |
| 4 | DAVx⁵, Feeder | `3fd2ccb` | 25 | 10 | 40,0% | 32,0% |
| 5 | Aegis, RedReader | `d5bb7a6` | 22 | 7 | 31,8% | 27,3% |
| 6 | KeePassDX, Breezy Weather | `226af5a` | 54 | 2 | 3,7% | 1,9% |
| 7 | Gadgetbridge, Wikipedia | `9c71644` | 107 | 3 | 2,8% | 2,8% |

- ⏳ Biểu đồ đường: precision tập phát triển vs precision holdout theo thời gian.
- Nhận định: precision holdout **không hội tụ**, dao động 2,8–40% theo **miền ứng dụng**; tập phát triển luôn
  cao hơn (35–42%). Mỗi miền sinh lớp FP riêng: namespace RSS (podcast), namespace XMPP (chat), từ vựng
  password/token (quản lý mật khẩu), mật mã giao thức thiết bị (đồ đeo).
- **Mục tiêu 2 (≥ 50% trên holdout) KHÔNG đạt** — nêu thẳng, phân tích nguyên nhân.

### 3.4.4. Hiệu quả điểm tin cậy (RQ3) ✅

Bảng 3.x — 15 app thật, điểm tin cậy theo từng cảnh báo (`ket-qua-test/m2_holdout7/test_output_all.txt`):

| Tầng | Riêng tầng | Cộng dồn (≥ tầng) |
|---|---|---|
| high | 80,0% (24/30) | 80,0% (24/30) |
| medium | 28,0% (23/82) | 42,0% (47/112) |
| low | 1,9% (3/162) | 18,2% (50/274) |

Holdout 7 (sạch với điểm tin cậy theo từng cảnh báo): high 2/5, ≥ medium 7,1% (3/42), **low 0/65 TP**.

- Kết luận dùng được: **tầng low là bộ lọc nhiễu** — bỏ low giảm 274 → 112 cảnh báo (−59%) trên 15 app, mất 3/50
  TP; trên holdout 7 giảm 107 → 42 (−61%) **không mất TP**.
- Tầng medium phụ thuộc miền app → không đạt 50% trên app mới.
- ⚠️ Tầng high: 80% nhưng phụ thuộc ❓2 (đa số là cấu hình mạng/backup); có FP do giao thức thiết bị (Gree, Fossil).
- ⏳ Biểu đồ cột chồng TP/FP theo tầng.

### 3.4.5. Phân tích báo nhầm theo miền ứng dụng ✅

Bảng 3.x "lớp FP — ví dụ — app — luật": namespace RSS/XMPP/GPX (NET-HTTP); tên khoá DB/SharedPreferences
(CRY-KEYLIT, 141 FP ở AntennaPod/Nextcloud); từ vựng miền mật khẩu (LOG-SENS/CRY-KEYLIT, KeePassDX);
mật mã giao thức thiết bị (CRY-WEAK/IV0/KEYHARD, Gadgetbridge); component cấu hình chỉ mở UI (CFG-EXPORT);
R8 gộp mã thư viện vào package app làm sai heuristic "app tự gửi action" (DAVx⁵ — UnifiedPush).

### 3.4.6. Các phát hiện bảo mật trên ứng dụng thật ✅ (❓4 cho mục đầu)

| Lớp phát hiện | Ứng dụng | Ghi chú |
|---|---|---|
| Activity xử lý chứng chỉ exported nhận cờ "tin cậy" từ intent → có thể thêm chứng chỉ vào kho tin cậy không cần người dùng | 1 ứng dụng đồng bộ (thư viện xác thực chứng chỉ) | **Ẩn danh hoá cho tới khi công bố có trách nhiệm**; mới phân tích tĩnh, độ tin cậy trung bình |
| Activity cắt/sửa ảnh exported trả dữ liệu ảnh qua `setResult` | Tusky, Conversations (thư viện CanHub cropper), Gadgetbridge | Rủi ro chuỗi cung ứng (M2) |
| `PreviewActivity` (công cụ debug Compose) lọt vào bản release, exported | Feeder, RedReader, Breezy Weather | Cấu hình build (`debugImplementation`) |
| Provider exported bỏ kiểm tra người gọi cho bảng metadata tệp | Nextcloud | Độ tin cậy trung bình |
| Sao lưu token/cookie không yêu cầu mã hoá (adb backup ≤ Android 11) | Jellyfin, RedReader | |
| Log mật khẩu ICE (toString của Credentials) | Conversations | Mức nhẹ |
| Thông tin xác thực/khoá API nhúng cứng | Feeder (Basic Auth đồng bộ), AntennaPod (PodcastIndex) | |
| Chép DB hỏng (chứa mật khẩu feed) ra bộ nhớ ngoài | AntennaPod | Chỉ khi DB hỏng |

---

## 3.5. Đối chứng với công cụ sẵn có

- ✅ JADX 1.5.0 / apktool 2.9.3 trên InsecureBankv2 (số liệu 2026-09-30, giữ từ khung cũ): JADX lộ bằng chứng
  6/12 (+2 gợi ý), 22,9 s/lượt; apktool 2/12, 7,8 s/lượt; cả hai 0 FP — nhưng **không tự kết luận**, người đọc
  phải tự tìm. `apiscan` tự động hoá đúng bước "tìm" này. `03_benchmark/so-sanh-tool/test_case_matrix_da_dien.xlsx`
- ⏳ MobSF (tĩnh) trên cùng IB + vài app thật (Docker đã có trên máy, cần bật daemon) — so precision/recall với
  `apiscan` trên cùng bộ nhãn. Đây là đối chứng mạnh nhất còn thiếu.
- ⏳ Phần động (Burp/ZAP/Frida) chỉ trên InsecureBankv2 nếu còn thời gian; nếu không → đưa vào hướng phát triển.

---

## 3.6. Thảo luận

1. **Bài học phương pháp**: precision đo trên app đã dùng để chỉnh luật bị thổi phồng; cần holdout. Đề xuất
   giao thức đánh giá công cụ phân tích tĩnh: đáp án có chủ đích (recall) + nhiều đợt holdout app thật (precision).
2. **Giới hạn của luật dựa trên mẫu**: precision phụ thuộc miền ứng dụng; điểm tin cậy giảm nhiễu tốt (tầng low)
   nhưng không biến cảnh báo medium thành đáng tin.
3. **Ảnh hưởng của chính sách gán nhãn** (❓2): trình bày độ nhạy — số liệu khi coi nhóm cấu hình mạng là FP.
4. **Hạn chế**:
   - Phạm vi quét theo package manifest: bỏ sót mã ở namespace khác (K-9, Nextcloud, Conversations) và
     applicationIdSuffix (KeePassDX — mặc định chỉ 1 cảnh báo).
   - Mã bị R8 tối ưu/đổi tên (hàm `replace` → `p.g0`, gộp lớp thư viện).
   - Phân tích luồng chỉ trong một tệp; không theo luồng xuyên lớp.
   - Chỉ tĩnh; một người gán nhãn; mỗi đợt holdout ít cảnh báo (22–169).
5. **Đạo đức**: chỉ app mã nguồn mở, chỉ phân tích tĩnh, không gửi request; công bố có trách nhiệm.

---

## 3.7. Kết luận chương

- RQ1: Có — 6 kỹ thuật giảm FP giữ recall 6/6 trên IB.
- RQ2: Precision tập phát triển (35–42%) không phản ánh app mới (holdout 2,8–40%, không hội tụ).
- RQ3: Điểm tin cậy giúp lọc ~60% cảnh báo mà gần như không mất lỗ hổng thật; chưa đạt precision ≥ 50% trên
  app mới ở ngưỡng ≥ medium.
- Đóng góp: công cụ + bộ dữ liệu 15 app / 529 nhãn có lý do + giao thức holdout + các phát hiện thật.
- Chuyển sang Kết luận & hướng phát triển (suy namespace mã, luồng xuyên lớp, tích hợp động, MobSF đối chứng).
