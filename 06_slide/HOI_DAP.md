# Chuẩn bị hỏi–đáp bảo vệ đồ án

Mọi số liệu dưới đây lấy từ Chương 3 (`05_bao-cao/Chuong3.md`) và các tệp minh chứng ghi ở từng câu. Không thêm số nào
chưa có trong luận văn. Mỗi câu: **trả lời ngắn (≈ 30 giây)** trước, sau đó là ý bổ sung nếu hội đồng hỏi sâu.

---

## A. Về kết quả chính

### 1. Mục tiêu precision ≥ 50% không đạt — vậy công cụ có giá trị gì?

**Ngắn:** Đúng, trên ứng dụng mới precision chỉ 2,8–40% qua 10 đợt holdout, em ghi rõ là không đạt. Giá trị của công cụ
nằm ở ba điểm: (1) recall 6/6 trên bộ đáp án ở ngưỡng khuyến nghị; (2) tầng tin cậy low lọc được khoảng 58% cảnh báo mà
gần như không mất lỗ hổng thật — trên holdout đợt 7–9 tầng low không có TP nào (0/71), đợt 10 cũng vậy (0/4); (3) so với MobSF trên cùng nhãn,
precision 17,2% so với 5,0%, tức là người kiểm thử đọc ít hơn khoảng 3,6 lần số cảnh báo để có cùng số lỗ hổng thật.

**Bổ sung:** Lọc ≥ medium: 331 → 138 cảnh báo (−58,3%), chỉ mất 3/57 TP. Kết quả "không đạt" cũng là một phát hiện: nó
cho thấy precision báo trên tập phát triển (40–63% ở ≥ medium) là con số lạc quan giả.
*Minh chứng:* Bảng 3.6, 3.7; `03_benchmark/ket-qua-test/final/summary.txt`.

### 2. Tại sao precision trên tập phát triển cao mà holdout lại thấp?

**Ngắn:** Vì luật được chỉnh dựa trên chính các ứng dụng đó — giống overfitting trong học máy. Mỗi miền ứng dụng mới sinh
một lớp báo nhầm luật chưa gặp: đợt 2 lộ việc CRY-KEYLIT nhận nhầm tên cột cơ sở dữ liệu là bí mật, đợt 3 lộ namespace
XMPP, đợt 6 là ứng dụng quản lý mật khẩu có từ vựng trùng đúng từ khoá của luật (password, token, secret).

**Bổ sung:** Giao thức holdout: đóng băng luật (ghi mã commit) → chạy trên 2 app mới → gán nhãn → đo → chỉ sau đó mới sửa
luật. Đây là đóng góp về phương pháp mà em đề xuất cho việc đánh giá công cụ phân tích tĩnh. *Minh chứng:* mục 3.3.4,
Hình 3.3.

### 3. Precision tầng high 80,6% có phải là con số đẹp quá không?

**Ngắn:** Con số này phụ thuộc vào quy ước gán nhãn và em đã công bố cả hai cách tính. 22/25 TP tầng high là cấu hình mạng
hoặc sao lưu ở cấp toàn ứng dụng. Nếu coi nhóm này là hành vi có chủ đích (FP) thì tầng high chỉ còn 9,7%.

**Bổ sung:** Vì vậy mọi so sánh với MobSF đều tính lại theo cả quy ước nhạy: apiscan 9,7% so với MobSF 3,0% — vẫn cao hơn.
*Minh chứng:* Bảng 3.7, mục 3.8 "Ảnh hưởng của quy ước gán nhãn".

### 4. Công cụ bỏ sót bao nhiêu lỗ hổng trên app thật?

**Ngắn:** Em đo trên 10 lỗ hổng do GitHub Security Lab công bố trên 5 app F-Droid, dùng đúng bản APK bị ảnh hưởng, tiêu
chí chấm ghi trước khi quét. Kết quả: phát hiện đúng cơ chế 3/10 (2/10 ở ≥ medium), chỉ đúng thành phần 7/10, bỏ sót
hoàn toàn 0/10.

**Bổ sung:** 3 lỗ hổng bắt đúng đều là content provider exported thiếu permission (lỗi cấu hình). 7 lỗ hổng còn lại là lỗi
logic (kiểm tra host deep link bằng `endsWith`, path traversal, trả lại intent qua `setResult`, AIDL không xác thực) —
công cụ chỉ dẫn người rà soát tới đúng thành phần trong mục "bề mặt tiếp nhận intent". Em không dùng 2 phát hiện của chính
apiscan để tránh thiên lệch. Có một sai lệch so với tiêu chí ghi trước (CVE-2021-41166 chấm trên Nextcloud 3.17.0 vì bản
3.18.0 đã sửa), đã ghi rõ. *Minh chứng:* Bảng 3.11, `03_benchmark/recall_cve/TIEU_CHI.md`.

**Nếu hỏi "đã sửa luật để bắt 2 CVE bị lọt chưa?":** Em cài 2 quy tắc rút ra từ phép đo này thành bộ luật v2 (tuỳ chọn,
không đổi mặc định) và đo bằng holdout đợt 10 trên 4 app mới, tiêu chí kết luận ghi trước. Trên 4 app đó, quy tắc 1 không
chạm cảnh báo nào, quy tắc 2 thêm 2 cảnh báo đều là FP — dưới ngưỡng 3 cảnh báo nên em ghi "chưa kết luận được". Trên dữ
liệu cũ (chỉ tham khảo), v2 nâng recall đúng cơ chế 3/10 → 4/10, nhưng 8/8 cảnh báo mới ngoài OsmAnd là service của thư
viện (Media3, UnifiedPush, Health Connect). Vì vậy em giữ v1 làm mặc định. *Minh chứng:* cuối mục 3.6,
`03_benchmark/ket-qua-test/m3_holdout10/KET_QUA.md`.

---

## B. Về phương pháp đánh giá

### 5. Nhãn TP/FP do một mình em gán — có đáng tin không?

**Ngắn:** Đây là hạn chế em đã ghi trong luận văn. Để giảm chủ quan, mỗi nhãn đều kèm lý do (608 dòng nhãn), quy ước gán
được công bố rõ, các mục có thể tranh luận gắn nhãn *borderline* và báo thêm precision "chặt" khi coi chúng là FP.

**Bổ sung:** Em đã chuẩn bị bộ đo đồng thuận: phiếu 80 cảnh báo lấy mẫu phân tầng (30 TP + 50 FP, seed 42), ẩn nhãn gốc,
có hướng dẫn gán và script tính Cohen's kappa kèm bootstrap — chỉ còn thiếu người gán thứ hai.
*Minh chứng:* `03_benchmark/ground-truth/dong_thuan/`, `04_code/scripts/dong_thuan.py`.
*(Nếu đã có người gán 2 trước buổi bảo vệ: thay bằng số kappa thật.)*

### 6. So sánh với MobSF có công bằng không?

**Ngắn:** Cùng 20 APK, cùng định nghĩa nhãn, MobSF cấu hình mặc định. Em tự nêu ba hạn chế: precision MobSF ước lượng từ
mẫu 100/1.182 cảnh báo; người gán đã biết nhãn của apiscan; apiscan đã được chỉnh luật trên chính các app này. Dù vậy, hai
khoảng tin cậy 95% không chồng nhau (MobSF 2,2–11,2%, apiscan 13,5–21,7%).

**Bổ sung:** Số TP tương đương (MobSF ước lượng ~59, KTC 26–132; apiscan 57) — khác biệt là chi phí kiểm tra. Trên
InsecureBankv2 MobSF mặc định chỉ 2/6 vì `SKIP_CLASS_PATH` chứa `com/android/` trùng package của app; chỉnh lại thì 3/6 +
1 một phần. MobSF cũng bắt được 1 TP mà apiscan bỏ sót (mã bị R8 dời sang `defpackage`). *Minh chứng:* Bảng 3.10,
`03_benchmark/ket-qua-test/doi_chung_mobsf.md`.

### 7. InsecureBankv2 là app cố ý có lỗi — đo recall trên đó có ý nghĩa gì?

**Ngắn:** Nó đóng vai ràng buộc: mọi kỹ thuật giảm báo nhầm phải giữ được 6/6 mục tĩnh, được kiểm tra tự động bằng bộ test
hồi quy (37 ca). Ràng buộc này từng bắt được một quy tắc sai: "thành phần không đọc intent thì xếp low" làm recall ở
≥ medium tụt còn 5/6 (mất `DoTransfer`), nên quy tắc bị loại.

**Bổ sung:** Em còn phát hiện chính đáp án có sai: V05 mô tả là "DES 56 bit" nhưng mã thật là AES/CBC khoá cứng + IV toàn
số 0; V04, V08, V09 và Bảng 2.7 cũng được hiệu chỉnh theo mã nguồn máy chủ. *Minh chứng:* Bảng 3.3.

### 8. Vì sao V03 (thiếu certificate pinning) không phát hiện được?

**Ngắn:** Đó là lỗi "vắng mặt một cơ chế": không có dòng mã nào để luật dựa trên dấu hiệu khớp vào. Em ghi rõ đây là giới
hạn của cách tiếp cận, không phải lỗi cài đặt.

---

## C. Về kỹ thuật

### 9. Công cụ khác gì so với grep từ khoá hay MobSF?

**Ngắn:** Bảy kỹ thuật xét ngữ cảnh, mỗi kỹ thuật sinh ra từ một lớp báo nhầm quan sát thật, cộng với tự suy phạm vi mã và
điểm tin cậy theo từng cảnh báo. Ví dụ: NET-HTTP chỉ cảnh báo khi chuỗi `http://` dùng làm địa chỉ kết nối (loại 42/42
báo nhầm namespace XMPP ở Conversations); CRY-KEYHARD lần ngược byte khoá về hằng (loại 14/14 báo nhầm); LOG-SENS chỉ
cảnh báo khi log in ra giá trị (loại 9/9 ở K-9 Mail).

**Bổ sung:** Tự suy phạm vi mã: KeePassDX quét theo package Manifest chỉ ra 1 cảnh báo, phạm vi tự suy ra 50; Nextcloud
9 → 46. *Minh chứng:* mục 3.2.3, 3.2.4.

### 10. Điểm tin cậy được tính thế nào? Có dùng học máy không?

**Ngắn:** Không dùng học máy. Điểm tin cậy là quy tắc theo tín hiệu của chính cảnh báo, đặt ra **trước khi đo** (Bảng 3.2):
high là bằng chứng trực tiếp, medium là dấu hiệu mạnh nhưng có thể có kiểm tra mà phân tích tĩnh không thấy, low là bề mặt
rủi ro chưa phải lỗ hổng. Tách riêng với mức nghiêm trọng (hậu quả nếu đúng).

**Bổ sung (nếu hỏi "sao không dùng ML"):** Tập nhãn chỉ 608 dòng trên 23 app, quá nhỏ để huấn luyện mà không overfit —
chính bài học của RQ2. Quy tắc giải thích được cho người kiểm thử vì sao cảnh báo bị hạ tầng.

### 11. Mã bị làm rối (R8/ProGuard) thì sao?

**Ngắn:** Ảnh hưởng thật và em đã ghi trong hạn chế: R8 đổi tên hàm (`replace` → `p.g0`) làm một số heuristic kết luận sai,
và dời mã vào package `defpackage` nằm ngoài phạm vi tự suy — chính là TP duy nhất MobSF tìm được mà apiscan bỏ sót.

### 12. Công cụ chạy nhanh cỡ nào, chạy nhiều app được không?

**Ngắn:** Phân tích trung vị 0,82 s/app (chậm nhất 6,92 s với Gadgetbridge, 4.918 tệp Java); cả quy trình một lệnh trên
InsecureBankv2 kể cả giải nén và JADX là 14 s. MobSF trung vị 84 s/app. Lệnh `batch` chạy 20 APK ra báo cáo từng app và
`index.html`/`summary.csv`; chạy lại cho đúng 331 cảnh báo như phiên bản cuối. *Minh chứng:* mục 3.4.7,
`03_benchmark/ket-qua-test/batch_20apk/`.

### 13. Phần quét động đóng góp gì, khi ZAP không tự tìm được lỗi nghiệp vụ?

**Ngắn:** Nó đo phân tích tĩnh giúp quét động được bao nhiêu. Không có bản đồ endpoint, ZAP quét được 0/6 endpoint API
(3 cảnh báo). Thêm bản đồ: 9 cảnh báo nhưng chỉ GET. Thêm POST có tham số lấy từ mã dịch ngược: 27 cảnh báo, 2 high là XSS
phản xạ ở `/login` và `/devlogin` — ngoài đáp án, đã xác minh tay. Khi công cụ tự trích phương thức và tên tham số từ mã
(thay cho yêu cầu viết tay), ZAP vẫn ra đúng 2 lỗi XSS này (26 cảnh báo, cả lệnh 123 giây).

**Bổ sung:** V07, V08 (BOLA), V09, V12 ZAP không tự phát hiện; em kiểm chứng thủ công bằng yêu cầu có chủ đích dựa trên bản
đồ endpoint, chỉ trên container cục bộ. Kết luận: lỗi phân quyền — trọng tâm của OWASP API Top 10 — cần yêu cầu có chủ
đích mà phân tích tĩnh giúp xác định. Hạn chế: một app, ZAP cấu hình mặc định; giá trị tham số (kể cả mật khẩu hợp lệ) không trích được
từ mã tĩnh; bộ trích chưa hỗ trợ OkHttp và mã bị R8 làm rối (Tusky). *Minh chứng:* Bảng 3.12, `03_benchmark/ket-qua-test/dynamic_ib/KET_QUA.md`.

### 14. Sao benchmark 7 công cụ ở Chương 2 chưa chạy đủ?

**Ngắn:** Trọng tâm đồ án đã chuyển sang xây công cụ (được thầy hướng dẫn đồng ý ngày 2026-10-04); benchmark giữ vai trò
đối chứng. Đã có số chạy thật cho JADX, apktool, MobSF và ZAP; Burp Suite và Frida cần emulator và chưa chạy.
*Minh chứng:* `03_benchmark/so-sanh-tool/test_case_matrix_da_dien.xlsx` (sheet "Tiêu chí đánh giá").

---

## D. Đạo đức và pháp lý

### 15. Em có quyền quét các app này không?

**Ngắn:** Chỉ dùng app có lỗ hổng có chủ đích (InsecureBankv2) và app mã nguồn mở tải từ F-Droid; với app thật chỉ phân
tích tĩnh, không gửi yêu cầu nào tới máy chủ của bên thứ ba. Quét động chỉ chạy trên backend InsecureBankv2 dựng cục bộ, và
lệnh `dynamic` có cổng an toàn: chỉ cho phép loopback/mạng riêng, hoặc phải có tệp văn bản cho phép.

### 16. Hai lỗ hổng nghiêm trọng em tìm được đã xử lý thế nào?

**Ngắn:** Em ẩn danh trong luận văn và báo riêng cho nhà phát triển theo quy trình công bố có trách nhiệm.
**Bổ sung:** Kiểm tra lại ngày 10/11/2026 trên bản mới nhất (phân tích tĩnh): cả hai vẫn chưa được sửa, nên em
tiếp tục ẩn danh trong luận văn, slide và mã nguồn công khai.
*(Còn phải tự điền trước buổi bảo vệ: ngày gửi báo cáo và kênh gửi, nhà phát triển đã phản hồi chưa.)*

---

## Câu chốt khi bị dồn về hạn chế

"Em không đạt mục tiêu precision 50% trên ứng dụng mới, và em báo cáo đúng như vậy. Đóng góp của đồ án là một công cụ chạy
được một lệnh, giữ recall trên bộ đáp án, đọc ít cảnh báo hơn MobSF khoảng 3,6 lần, cùng với một giao thức đánh giá
holdout cho thấy vì sao các con số precision báo trên tập phát triển không đáng tin."
