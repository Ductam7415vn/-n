# Holdout đợt 10 — kết quả (2026-11-10)

Tiêu chí ghi trước: `TIEU_CHI.md` (commit `0a96461`). Luật đóng băng ở `9fa79f2`. Nhãn:
`03_benchmark/ground-truth/{organicmaps,etar,florisboard,opentracks}_labels.json` (19 dòng, gán hợp nhất cho v1 và v2).
Chấm lại: `python3 cham.py holdout` → `ket_qua_holdout.txt`; cũng khớp `04_code/scripts/test_groundtruth.py --eval`.

## 1. Precision trên 4 ứng dụng holdout

| Bộ luật | Cảnh báo | TP | Precision | Chặt | ≥ medium | ≥ medium, chặt |
|---|---|---|---|---|---|---|
| v1 (Chương 3) | 17 | 2 | 11,8% | 5,9% | 15,4% (2/13) | 7,7% (1/13) |
| v2 | 19 | 2 | 10,5% | 5,3% | 13,3% (2/15) | 6,7% (1/15) |

Theo tầng (v1): high 1/1, medium 1/12, low 0/4 — tầng low tiếp tục không chứa TP. Hai TP đều là NET-NSC của Organic Maps
(cleartext ở base-config; mục domain-config là borderline vì trùng gốc).

Theo ứng dụng (v1): Organic Maps 2/8, Etar 0/2, FlorisBoard 0/2, OpenTracks 0/5. FP chủ yếu là *intended*: activity-alias
trỏ về màn hình chính, public API của OpenTracks (mặc định tắt, borderline), WebView chỉ nạp nội dung đóng gói hoặc có CSP
chặn script; FP *pattern*: hằng `"http://"` dùng để cắt tiền tố, tên khoá Bundle/Navigation bị coi là khoá mật mã, từ
`tokenizable` khớp từ khoá log nhạy cảm.

## 2. Hai thay đổi của v2

| Thay đổi | Cảnh báo bị tác động trên holdout | TP | Kết luận theo tiêu chí ghi trước |
|---|---|---|---|
| (1) Không hạ CFG-EXPORT xuống low chỉ vì mã có gọi API kiểm tra bên gọi | 0 | — | Chưa kết luận được (< 3 cảnh báo) |
| (2) Service exported, không permission, nhận action tuỳ biến → cảnh báo | 2 | 0 | Chưa kết luận được (< 3 cảnh báo) |

Hai cảnh báo mới của thay đổi (2) đều là FP và đều là service mà **thư viện** khai báo, có xác thực bên gọi trong mã:
- Organic Maps `AndroidAutoService` (CarAppService): `createHostValidator()` chỉ cho host trong danh sách chữ ký.
- OpenTracks `HealthDataSdkService` (Health Connect): kiểm tra `getPackagesForUid(Binder.getCallingUid())` với danh sách cho phép.

Không có thành phần nào trong 4 ứng dụng rơi vào thay đổi (1), nên đợt này không cho thông tin về nó.

## 3. Số liệu tham khảo (không phải holdout)

Chạy lại v1 và v2 trên 19 ứng dụng của tập phát triển và 5 bản bị lỗi của phép đo CVE (`tham_khao/`, APK đối chiếu
SHA-256 với lần đo trước). Lượt v1 trên 19 ứng dụng tái lập đúng số của Chương 3: 331 cảnh báo, 17,2% (57/331),
≥ medium 39,1% (54/138).

**Tập phát triển** (`python3 cham.py tham_khao dev` → `tham_khao/ket_qua_dev.txt`):
- Thay đổi (1): 2 cảnh báo low → medium — Nextcloud `FileContentProvider` (TP) và K-9 Mail `SettingsProvider` (FP).
  Precision ≥ medium 39,1% → 39,3% (55/140).
- Thay đổi (2): 6 cảnh báo mới, **chưa gán nhãn**: 3 service Media3 (Nextcloud, AntennaPod, Jellyfin), 2
  `RaiseToForegroundService` của UnifiedPush (DAVx⁵, Tusky), 1 `HealthDataSdkService` (Gadgetbridge). Cả 6 đều là service
  của thư viện, nhận action giao thức của thư viện (`androidx.*`, `org.unifiedpush.*`) — cùng dạng với 2 FP của holdout.
  Đây là nhận định từ Manifest, chưa đối chiếu mã từng service.

**10 lỗ hổng đã công bố** (`python3 cham.py tham_khao cve` → `tham_khao/ket_qua_cve.txt`, chấm theo
`03_benchmark/recall_cve/TIEU_CHI.md`):
- Thay đổi (1): CVE-2021-43863 (Nextcloud 3.17.0 `FileContentProvider`) từ low lên medium.
- Thay đổi (2): CVE-2026-65995 (OsmAnd `OsmandAidlServiceV2`) chuyển từ bề mặt tiếp nhận thành cảnh báo CFG-EXPORT
  medium. Thêm 2 cảnh báo khác trên OsmAnd: `OsmandAidlService` (AIDL bản cũ) và `NavigationCarAppService` (Android Auto).
- Recall đúng cơ chế: v1 3/10 (2/10 ở ≥ medium) → v2 4/10 (4/10 ở ≥ medium). Hai quy tắc được rút ra *từ chính* hai
  CVE này, nên đây là số trên tập đã dùng để thiết kế, không phải bằng chứng độc lập.

## 4. Nhận xét

- Theo tiêu chí ghi trước, đợt 10 **không đủ dữ liệu để giữ hay bỏ** thay đổi nào. Bốn ứng dụng mới chỉ sinh 2 cảnh báo bị
  tác động, ít hơn ngưỡng 3.
- Chiều của dữ liệu khác nhau giữa hai thay đổi:
  - (1) có lợi ở mọi nơi đo được: trên tập phát triển 1/2 cảnh báo bị tác động là TP (50%, không thấp hơn precision ≥ medium 39,1% của v1), và
    đưa một CVE thật lên ngưỡng khuyến nghị.
  - (2) bắt được một CVE thật, nhưng trên ứng dụng mới 0/2 TP; 8/8 cảnh báo mới ngoài OsmAnd là service của thư viện
    dùng action giao thức. Heuristic "action tuỳ biến" coi action của thư viện là tuỳ biến của app.
- Quyết định: **giữ v1 làm mặc định** (đúng số của Chương 3); v2 vẫn là tuỳ chọn `--export-rules v2`. Muốn kết luận cần
  một đợt holdout chọn theo tiêu chí có nhiều provider/service exported hơn, hoặc gộp nhiều đợt.
- Hướng sửa (2) rút ra từ đợt này — chưa đo, phải qua holdout mới: không coi action thuộc namespace của thư viện phổ biến
  (`androidx.`, `org.unifiedpush.`) là tuỳ biến.
- Precision holdout của v1 (11,8%) nằm trong dải 2,8–40% của chín đợt trước; khoảng cách ≥ medium với tập phát triển tại
  thời điểm đóng băng là 39,1% − 15,4% = 23,7 điểm phần trăm.
