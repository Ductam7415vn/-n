# LOOP BRIEF — Vòng lặp tự động xây–đo–cải thiện APIScan

Dán brief này cho session mới (Opus 5.5) khi muốn chạy vòng lặp tự động phát triển công cụ. Có thể
kết hợp với skill `agentic-research-loop` nếu cần điều phối nhiều subagent, nhưng với công việc này
một vòng lặp đơn tuần tự là đủ.

## Mục tiêu của vòng lặp

Cải thiện `apiscan` qua từng vòng, tối ưu hai chỉ số **cùng lúc**:
- **Recall trên InsecureBankv2 = 100%** (ràng buộc cứng — không được giảm).
- **Precision trên app thật tăng dần** (NewPipe + app mã nguồn mở khác), mục tiêu ≥ 50%.

## Bộ đáp án chuẩn (ground truth) để tự chấm mỗi vòng

- **InsecureBankv2**: 6 lỗ hổng tĩnh phải luôn bắt được: V01 (khoá cứng, `CryptoClass.java:22`),
  V02 (cleartext/targetSdk), V05 (IV tĩnh, `CryptoClass.java:23`), V06 (exported), V07 (`/devlogin`),
  V11 (allowBackup). Có thể bắt thêm V04, V10.
- **NewPipe 0.29.1**: nhãn TP/FP gán tay cho từng cảnh báo ở `03_benchmark/ground-truth/newpipe_labels.json`
  (1 TP = allowBackup, 18 FP). Precision = TP/(TP+FP) theo nhãn. Cảnh báo MỚI chưa có nhãn → phải gán tay
  (đối chiếu mã) trước khi báo số; KHÔNG viết luật lọc dựa vào tên class cụ thể của app (overfit).

Viết sẵn một script test (`04_code/scripts/test_groundtruth.py`) khẳng định hai điều trên — chạy mỗi
vòng, FAIL nếu recall InsecureBankv2 < 100%.

## Giao thức mỗi vòng lặp

1. **Chọn 1 cải tiến** từ ROADMAP (vd: thêm luật lọc `NET-HTTP`).
2. **Sửa code** `apiscan`/`static_scan.py`.
3. **Chạy lại trên 2 app** (InsecureBankv2 + NewPipe); nếu có thì thêm app mã nguồn mở thứ 3.
4. **Đo**: recall InsecureBankv2 (phải = 100%), precision NewPipe (so vòng trước).
5. **Ghi vào `docs/PROGRESS.md`**: thay đổi gì, recall/precision trước→sau, FP nào hết, FP nào mới.
6. **Dừng vòng** nếu: đạt precision mục tiêu, hoặc cải tiến không còn tăng, hoặc recall tụt (phải
   revert ngay).

## Dữ liệu đầu vào có sẵn / cách lấy thêm

- InsecureBankv2 APK: `raw.githubusercontent.com/dineshshetty/Android-InsecureBankv2/master/InsecureBankv2.apk`.
- App mã nguồn mở: F-Droid (`f-droid.org/repo/<pkg>_<vc>.apk`; lấy version qua
  `f-droid.org/api/v1/packages/<pkg>`). Ưu tiên app có gọi API để kiểm tra trích endpoint.
- Container Claude chạy được apktool/JADX; KHÔNG chạy được Docker/emulator (phần động để máy Mac).

## Rào chắn (guardrails — không vi phạm)

- Chỉ phân tích **tĩnh** app của bên thứ ba; chỉ app **mã nguồn mở** hoặc có phép.
- **Không** sinh mã khai thác; công cụ chỉ phát hiện và báo cáo.
- **Không bịa số liệu**: mỗi con số kèm lệnh chạy + file kết quả.
- Mỗi cảnh báo trong báo cáo phải truy được về tệp:dòng để người kiểm chứng.

## Tiêu chí "xong vòng lặp"

`apiscan` một lệnh ra báo cáo, recall InsecureBankv2 = 100%, precision app thật ≥ 50% trên ≥ 3 app,
có điểm tin cậy và bản đồ endpoint. Khi đó chuyển sang M4/M5 (động + đóng gói + viết Chương 3).
