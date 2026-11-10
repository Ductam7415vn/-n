# BÀN GIAO SESSION — Đọc đầu tiên

Tài liệu này giúp một session Claude mới (Opus 5.5) tiếp tục đồ án **mà không mất ngữ cảnh**.
Đọc theo thứ tự: `CLAUDE.md` → `HANDOFF.md` (file này) → `docs/PROGRESS.md` → `docs/ROADMAP_TOOL.md`.
Khi muốn chạy vòng lặp tự động xây–đo–cải thiện: đọc `docs/LOOP_BRIEF.md`.

---

## 1. Một câu tóm tắt

Đồ án đã chuyển từ *"nghiên cứu so sánh công cụ"* sang *"xây một công cụ phát hiện lỗ hổng
Android/API thật, có output dùng được"*, tên `apiscan`. Nền tảng đã có hai script chạy thật
(`static_scan.py`, `pipeline.py`) và hai bộ số liệu thật (InsecureBankv2, NewPipe).

## 2. Vì sao đổi hướng (bối cảnh để tự tin trả lời hội đồng)

- Hướng benchmark thuần không có đóng góp mới, giá trị thực tế thấp.
- Khi chạy thật, công cụ tĩnh đạt **precision ~100% trên app có chủ đích nhưng rớt còn 5,3% trên app
  thật** (NewPipe) — có cả trường hợp gắn cờ nhầm chính mã bảo mật tốt (code nâng cấp http→https).
- → Giá trị thật nằm ở việc **xây một công cụ biết tự giảm báo nhầm** và cho **output dùng được**
  (báo cáo + bản đồ endpoint), chứ không phải một bảng so sánh.

## 3. Tài sản đã có (đường dẫn trên máy Mac: `~/Desktop/Đồ án/`)

**Code (`04_code/scripts/`):**
- `static_scan.py` — quét TĨNH: đọc output apktool (Manifest/smali) + JADX (Java), áp 12+ quy tắc
  (khoá cứng, IV tĩnh, mã hoá yếu, cleartext, exported, allowBackup, debuggable, log nhạy cảm, bộ
  nhớ ngoài, WebView, endpoint ẩn), gắn nhãn OWASP Mobile 2024, trích bản đồ endpoint. Xuất JSON+HTML.
  CHỈ ĐỌC FILE, không chạm mạng.
- ⚠️ `pipeline.py`, `README_pipeline.md`, `pipeline_demo_report.html` **không còn trên máy** (kiểm
  2026-10-03) — mô tả dưới là của bản cũ, cần tìm lại hoặc viết lại.
- `pipeline.py` — tích hợp MobSF (REST) + OWASP ZAP (REST), gộp finding, gắn nhãn OWASP, xuất báo
  cáo HTML hợp nhất. Có chế độ `--*-json` để gộp offline. Đã test dữ liệu mẫu.
- `README_pipeline.md` — hướng dẫn chạy pipeline.
- `pipeline_demo_report.html` — báo cáo mẫu.

**Kết quả thật (`03_benchmark/ket-qua-test/`):**
- `static_findings.md` — finding tĩnh JADX/apktool trên InsecureBankv2 (kèm tệp:dòng).
- `validation_insecurebankv2.md` — kiểm chứng: recall 100% nhóm tĩnh, precision ~100%, 1 FP đã sửa.
- `realworld_newpipe.md` — chạy NewPipe: 19 cảnh báo, 145 endpoint, precision 5,3% (1/19), phân tích FP.

**Nhãn gán tay (`03_benchmark/ground-truth/`):** `insecurebankv2_labels.json` (24/24 TP),
`newpipe_labels.json` (1 TP / 18 FP). `test_groundtruth.py` tính precision từ đây; cảnh báo mới chưa có
nhãn sẽ được liệt kê để gán thêm.
- `ib_static_report.html`, `newpipe_report.html` — báo cáo HTML xem được.

**Benchmark (`03_benchmark/so-sanh-tool/`):**
- `test_case_matrix_da_dien.xlsx` — ma trận + 7 tiêu chí; đã điền số thật cho JADX, apktool.
- (bản gốc `test_case_matrix.xlsx` vẫn còn.)

**Luận văn (`05_bao-cao/`):**
- `Báo cáo đợt 1.docx` (Chương 1), `Báo cáo đợt 2.docx` (Chương 2) — xong.
- `Chuong3_khung.md` — khung Chương 3, phần tĩnh đã có số liệu.
- `Báo cáo thực tập.docx` — báo cáo thực tập BetaSoft (việc khác, không liên quan công cụ này).

## 4. Hai mốc số liệu THẬT (không được bịa thêm)

| | InsecureBankv2 (có chủ đích) | NewPipe 0.29.1 (app thật, mã nguồn mở) |
|---|---|---|
| APK SHA-256 | `b18af2a0…94a4` | `1d66d19e…b7e8` |
| Tổng cảnh báo | 24 | 19 |
| Recall nhóm tĩnh | 6/6 = 100% (+ bonus V04, V10) | — |
| Precision như "lỗ hổng" (nhãn gán tay) | 100% (24/24) | 5,3% (1/19) |
| Endpoint trích được | 6 | 145 |
| Missed | V03 (thiếu pinning — lỗi "vắng mặt") | — |

Các FP điển hình trên NewPipe (dùng để viết luật lọc ở M1/M2):
1. `NET-HTTP` gắn cờ mã **nâng cấp http→https** (`replace("http://","https://")`, `startsWith("http://")`).
2. `LOG-SENS` gắn cờ log easter egg "You unlocked a secret unicorn".
3. `CFG-EXPORT` gắn cờ các thành phần **buộc phải exported** (MainActivity có LAUNCHER, media button…).
4. `STO-EXT` gắn cờ truy cập bộ nhớ ngoài vốn là **chức năng chính** (tải video).

## 5. Việc tiếp theo (ưu tiên)

1. ~~Trao đổi với thầy Phạm Duy Trung~~ — ✅ thầy Phạm Duy Trung đã cho phép đổi trọng tâm sang xây công cụ `apiscan` (sinh viên xác nhận ngày 2026-10-04). Còn: cập nhật đề cương cho khớp.
2. **M1**: hợp nhất 2 script thành CLI `apiscan` + viết luật lọc 4 loại FP ở trên. Giữ recall 100%
   trên InsecureBankv2 (có test tự động trong `docs/LOOP_BRIEF.md`).
3. Theo `docs/ROADMAP_TOOL.md` các mốc M2–M5.

## 5b. Chạy công cụ (2026-10-04)

```bash
python3 04_code/scripts/apiscan.py scan 04_code/target-app/InsecureBankv2.apk --min-confidence medium
python3 -m unittest discover -s 04_code/tests -v
python3 04_code/scripts/compare_mobsf.py summary   # đối chứng MobSF (kết quả: 03_benchmark/ket-qua-test/doi_chung_mobsf.md)
# 2026-11-08:
python3 04_code/scripts/apiscan.py batch 04_code/target-app -o out/          # → out/index.html, summary.csv
python3 04_code/scripts/apiscan.py scan app.apk --config 04_code/scripts/apiscan.example.yml
python3 04_code/scripts/apiscan.py baseline out/<app>/report.json -o apiscan.yml
python3 04_code/scripts/apiscan.py dynamic out/InsecureBankv2/report.json --target http://127.0.0.1:8888 \
    --zap http://127.0.0.1:8090 --zap-key <khoá> --seed-requests 04_code/dynamic/ib_seed_requests.txt
```
Thư mục đồ án hiện nằm trên ổ SSD ngoài: `/Volumes/BetaSoft/Desktop/Đồ án` (colima/Docker cũng lưu trên ổ này).

## 6. Giới hạn môi trường

- Container cloud của Claude: có Java, chạy được JADX/apktool/`static_scan.py`, KHÔNG có Docker
  daemon → MobSF/ZAP/emulator phải chạy trên máy Mac.
- Tải APK: raw.githubusercontent.com của repo InsecureBankv2 và f-droid.org tải được; github.com bị
  chặn 403 trong container.

## 7. Harness đã setup kèm (xem mục dưới và `docs/`)

- `.claude/settings.json` — hooks SessionStart/Stop + permissions.
- `.claude/skills/android-api-security/SKILL.md` — đã cập nhật sang hướng xây công cụ.
- `docs/PROGRESS.md` — sổ tiến độ (cập nhật sau mỗi phiên).
- `docs/ROADMAP_TOOL.md` — lộ trình công cụ + định nghĩa "output thật".
- `docs/LOOP_BRIEF.md` — brief để chạy vòng lặp tự động xây–đo–cải thiện.
- `docs/TRAO_DOI_GVHD.md` — nội dung trao đổi với thầy về đổi hướng.
