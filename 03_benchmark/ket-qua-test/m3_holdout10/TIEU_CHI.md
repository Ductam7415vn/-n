# Holdout đợt 10 — tiêu chí ghi trước khi quét (2026-11-08)

Mục đích: đo trên ứng dụng mới hai thay đổi luật CFG-EXPORT rút ra từ phép đo recall trên 10 lỗ hổng đã công bố
(`03_benchmark/recall_cve/KET_QUA.md`, mục "Phân tích sau khi xem kết quả"). Tệp này được commit **trước khi** tải APK.

## Luật đóng băng

Commit `9fa79f2`. Hai bộ luật chạy trên cùng APK, cùng phạm vi tự suy:

- **v1** (mặc định, bộ luật của Chương 3): `apiscan.py scan <apk>`
- **v2**: `apiscan.py scan <apk> --export-rules v2`, khác v1 đúng hai điểm:
  1. CFG-EXPORT không còn bị hạ xuống low chỉ vì mã lớp có gọi API kiểm tra bên gọi (`getCallingUid`,
     `checkCallingPermission`…); giữ mức medium mặc định.
  2. Service exported, không permission, nhận action tuỳ biến (không bắt đầu bằng `android.`) mà app không tự gửi →
     cảnh báo CFG-EXPORT (medium) thay vì mục bề mặt tiếp nhận.

Không sửa luật, điểm tin cậy hay phạm vi trong đợt này cho tới khi gán nhãn xong.

## Ứng dụng

Bốn ứng dụng thay vì hai như các đợt trước, vì hai thay đổi chỉ tác động tới một luật nên cần nhiều thành phần exported
hơn. Tiêu chí chọn (không dựa trên Manifest, chưa mở APK): miền chức năng chưa có trong 19 ứng dụng của tập đánh giá và
5 ứng dụng của phép đo recall; ứng dụng phổ biến trên F-Droid; bản mới nhất trong chỉ mục `index-v2.json` (tải
2026-11-08, last-modified 2026-11-06).

| Ứng dụng | Miền | Phiên bản | Tệp | SHA-256 theo chỉ mục F-Droid |
|---|---|---|---|---|
| Organic Maps | bản đồ, dẫn đường | 2026.09.29-32-FDroid | `app.organicmaps_26092932.apk` | `654a736d43317084f13560281fe7013f869800610e9d6036b6789d9c9e07f8bc` |
| Etar | lịch | 1.0.57 | `ws.xsoh.etar_57.apk` | `dae01d93c8920aa63845868db2190bcc4aa6ff8410b1289de1ce27b1bb89c599` |
| FlorisBoard | bàn phím | 0.5.2 | `dev.patrickgold.florisboard_117.apk` | `d8ef30b212730e7c005250f3f9a8bcee4afd1605b66efaa15f7f59a89cffa9b5` |
| OpenTracks | theo dõi thể thao | v4.29.0 | `de.dennisguse.opentracks_6766.apk` | `f63ed60e2a4f1b3d878671bfde2150ceaa89e484618b91390500e1a583694cc1` |

## Đo gì

- Gán nhãn **hợp nhất** mọi cảnh báo của v1 và v2 (cùng định nghĩa TP/FP/borderline, cùng quy ước với các đợt trước).
- Chỉ số chính: precision của v1 và v2 trên 4 ứng dụng — mọi cảnh báo, ≥ medium, và chặt (borderline → FP).
- Chỉ số riêng cho hai thay đổi: số cảnh báo đổi tầng (1) và số cảnh báo mới (2), mỗi nhóm bao nhiêu TP.
- Kết luận cho mỗi thay đổi:
  - **Giữ** nếu nhóm cảnh báo bị tác động có precision không thấp hơn precision ≥ medium của v1 trên cùng đợt.
  - **Bỏ** nếu thấp hơn.
  - **Chưa kết luận được** nếu nhóm bị tác động có ít hơn 3 cảnh báo.
- Số liệu tham khảo (đo trên tập phát triển, không phải holdout): ảnh hưởng của v2 trên 19 ứng dụng cũ và trên 10 lỗ
  hổng đã công bố.
