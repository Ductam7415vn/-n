# Đồ án → Công cụ: Phát hiện lỗ hổng bảo mật API/Android (APIScan)

> ⚠️ ĐỌC FILE NÀY ĐẦU MỖI SESSION. Sau đó đọc `HANDOFF.md` và `docs/PROGRESS.md`.
> Ngôn ngữ làm việc: **tiếng Việt**.

## Bước ngoặt (2026-10-03): đổi trọng tâm

Đồ án **không còn chỉ là nghiên cứu/benchmark**. Trọng tâm mới là **xây một CÔNG CỤ thật có
OUTPUT dùng được**:

- **Tên công cụ (đề xuất):** `apiscan`
- **Công cụ làm gì:** nhận một file APK (hoặc nhiều file) → cho ra **báo cáo lỗ hổng** (HTML + JSON)
  gắn nhãn OWASP, **bản đồ endpoint API**, và **điểm tin cậy** cho từng cảnh báo.
- **Phần benchmark 7 công cụ** (MobSF/Burp/ZAP/Frida/JADX/apktool) **vẫn giữ nhưng hạ xuống vai trò
  phụ**: dùng để đối chứng và chọn kỹ thuật cho `apiscan`, không còn là mục tiêu cuối.

## Mục tiêu đo được của công cụ

1. Một lệnh: `apiscan scan app.apk` → ra báo cáo + endpoint map + JSON.
2. **Giữ recall 100%** trên nhóm lỗ hổng tĩnh của InsecureBankv2 (đáp án V01–V12).
3. **Tăng precision trên app thật**: baseline NewPipe 5,3% = 1/19 theo nhãn gán tay, hiện 33,3% = 1/3 sau lọc `NET-HTTP` + `CFG-EXPORT` + `LOG-SENS` + `STO-EXT`; gộp 3 app thật (+Tusky, K-9 Mail) 35,7% = 5/14; holdout đợt 2 (AntennaPod, Nextcloud) chỉ 5,3% = 9/169 do CRY-KEYLIT → sau sửa CRY-KEYLIT gộp 5 app 34,9% = 15/43 (tập phát triển); **holdout đợt 3 (Conversations, Jellyfin) 15,3% = 13/85, chặt 9,4%** → sau NET-HTTP theo ngữ cảnh gộp 7 app 35,0% = 28/80 (tập phát triển); **holdout đợt 4 (DAVx5, Feeder) 40,0% = 10/25, chặt 32,0%** → sau CRY-KEYHARD gộp 9 app 41,8% = 38/91 (tập phát triển); holdout đợt 5 (Aegis, RedReader) 31,8% = 7/22; **holdout đợt 6 (KeePassDX, Breezy) 3,7% = 2/54** — điểm tin cậy M2 chưa kiểm chứng được. Mục tiêu ≥ 50% sau khi
   thêm lọc + điểm tin cậy.
4. Chạy được batch nhiều APK, có bảng tổng hợp.
5. (Tùy chọn, chỉ khi có phép chủ app) tích hợp quét động qua `pipeline.py` (MobSF + ZAP).

## Nguyên tắc bắt buộc (đạo đức & an toàn — KHÔNG vi phạm)

- Công cụ là **phòng thủ**: chỉ ĐỌC/phân tích APK, **không** sinh mã khai thác tấn công.
- Với app của người khác: **chỉ phân tích tĩnh** (đọc APK). **Không** quét động/gửi request tới
  server của họ nếu chưa có văn bản cho phép.
- Chỉ thử nghiệm trên: app có chủ đích (InsecureBankv2), app **mã nguồn mở** (NewPipe…), hoặc app
  của BetaSoft nếu công ty đồng ý bằng văn bản.
- **Không bịa số liệu.** Mọi con số phải từ lần chạy thật, có file minh chứng.

## Hiện trạng (tính đến 2026-10-03)

| Hạng mục | Trạng thái | File |
|---|---|---|
| `apiscan.py scan app.apk` — một lệnh: tự giải nén, tự suy phạm vi mã, gọi bộ luật `static_scan.py`, xuất HTML/JSON + điểm tin cậy | ✅ chạy thật | `04_code/scripts/apiscan.py`, `static_scan.py` |
| Bộ test hồi quy (`python3 -m unittest discover -s 04_code/tests -v`) | ✅ 48 ca (2026-11-08) | `04_code/tests/` |
| `apiscan.py batch` — nhiều APK → báo cáo từng app + `index.html`/`summary.csv` | ✅ chạy thật 20 APK (2026-11-08) | `apiscan.py`, `03_benchmark/ket-qua-test/batch_20apk/` |
| Cấu hình YAML + suppression (`--config`, `baseline`) | ✅ (2026-11-08) | `apiscan_config.py`, `apiscan.example.yml` |
| `apiscan.py dynamic` — ZAP dẫn đường bằng bản đồ endpoint, gộp tĩnh + động (+ MobSF) | ✅ chạy thật trên backend IB (2026-11-08): XSS ×2; V07/V08/V09/V12 kiểm chứng tay; yêu cầu mẫu tự trích từ mã (HttpClient/Retrofit) cho cùng 2 XSS | `dynamic_scan.py`, `03_benchmark/ket-qua-test/dynamic_ib/` |
| Kiểm chứng trên InsecureBankv2 | ✅ recall 100% nhóm tĩnh, precision ~100% | `03_benchmark/ket-qua-test/validation_insecurebankv2.md` |
| Chạy thật trên NewPipe (app mã nguồn mở) | ✅ precision 5,3% (1/19, nhãn gán tay) → phát hiện nghiên cứu chính | `03_benchmark/ket-qua-test/realworld_newpipe.md` |
| Đối chứng MobSF trên cùng bộ nhãn (19 app + IB) | ✅ MobSF precision 5,0% (mẫu 100) vs apiscan 17,2%; IB 2/6 vs 6/6 | `03_benchmark/ket-qua-test/doi_chung_mobsf.md` |
| Benchmark 7 tool | 🔶 mới có JADX + apktool + MobSF (số thật) | `03_benchmark/so-sanh-tool/test_case_matrix_da_dien.xlsx` |
| Luận văn Chương 1, 2 | ✅ xong | `05_bao-cao/Báo cáo đợt 1/2.docx` |
| Luận văn Chương 3 | ✅ bản thảo đầy đủ (2026-10-04) — chờ chốt ❓ nhãn cấu hình mạng, borderline | `05_bao-cao/Chuong3.md` → `Chuong3_apiscan.docx` (`xuat_docx.py`), hình ở `05_bao-cao/hinh/` |
| Recall trên lỗ hổng đã công bố (10 CVE/GHSL, 5 app) | ✅ đúng cơ chế 3/10, đúng thành phần 7/10, bỏ sót 0 (2026-11-08) | `03_benchmark/recall_cve/` |
| Bộ đo đồng thuận gán nhãn (phiếu 80 mục + kappa) | 🔶 sẵn sàng, chưa có người gán 2 | `03_benchmark/ground-truth/dong_thuan/`, `dong_thuan.py` |
| Quét động (Burp/ZAP/Frida) | ❌ cần máy Mac + emulator | — |
| Luận văn hoàn chỉnh (bìa → Chương 1–3 → Kết luận → TLTK → Phụ lục) | ✅ bản ghép 2026-10-04 — mở Word cập nhật mục lục | `05_bao-cao/ghep_luan_van.py` → `DoAnTotNghiep_NguyenDucTam.docx`, `KetLuan.md` |
| Slide bảo vệ | ✅ 16 slide (2026-11-08), Artifact Slides | `06_slide/README.md` (link) |

## Môi trường lab (máy Mac — Apple Silicon)

- Emulator: Android Studio AVD ARM64, Android 13 (API 33). KHÔNG Genymotion.
- Target có chủ đích: InsecureBankv2 + backend Flask (port 8888).
- MobSF/ZAP qua Docker. (Container cloud của Claude KHÔNG chạy được Docker/emulator — các bước này
  phải chạy trên máy Mac.)

## Chuẩn OWASP

Dùng **OWASP Mobile Top 10 – 2024** và **API Security Top 10 – 2023**. KHÔNG dùng Mobile 2016.

## Ghi chú / Quyết định

- [2026-06-26] Hướng ban đầu: nghiên cứu & benchmark 7 tool; chọn InsecureBankv2.
- [2026-08-04] Thêm `pipeline.py` (MobSF+ZAP) làm đóng góp kỹ thuật.
- [2026-09-30] Chạy thật JADX+apktool; phát hiện **đáp án V05 sai** ("DES" → thực tế AES/CBC khoá
  cứng + IV tĩnh). Cần sửa trong luận văn.
- [2026-10-03] **ĐỔI TRỌNG TÂM sang xây công cụ `apiscan`.** Viết `static_scan.py`, kiểm chứng trên
  InsecureBankv2 (recall 100%), chạy thật NewPipe (precision 6% → bài học precision).
- [2026-10-03] Tách repo git riêng cho `Đồ án/` (trước đó git root là `~/Desktop`, 0 file được track).
- [2026-10-03] Precision đo bằng **nhãn gán tay** (`03_benchmark/ground-truth/*_labels.json`), không còn
  công thức `(tổng − FP đã liệt kê)/tổng` (cho ra 58% sai). Số NewPipe cũ 17/146/6% không tái lập được →
  dùng 19 cảnh báo / 145 endpoint / 5,3%. Recall InsecureBankv2 ghi là "6/6 mục tĩnh", không phải "V01–V12".
- [2026-10-04] Phát hiện nghi lỗ hổng ([ẩn danh A]) → công bố có trách nhiệm cho nhà phát triển trước khi công khai chi tiết.
- [2026-10-04] Phát hiện thứ hai cần công bố có trách nhiệm ([ẩn danh B], holdout 8, phân tích tĩnh).
- [x] [2026-10-04] GVHD: thầy Phạm Duy Trung đã cho phép đổi trọng tâm sang xây công cụ `apiscan` (sinh viên xác nhận ngày 2026-10-04).
- [x] Cập nhật đề cương (`05_bao-cao/de_cuong_DA.docx`) cho khớp hướng mới (commit cf8da06).

## TODO (xem roadmap chi tiết ở `docs/ROADMAP_TOOL.md`)

- [x] M1 (phần tĩnh): CLI `apiscan.py scan`, lọc FP, tự suy phạm vi mã, test hồi quy. Còn: `batch`, `dynamic`.
- [x] M2: điểm tin cậy theo từng cảnh báo — holdout 7: ≥ medium 7,1%, nhưng tầng low không chứa TP (0/65) → dùng
  được như bộ lọc nhiễu; mục tiêu ≥50% chưa đạt trên app mới. Suppression + cấu hình YAML ✅ 2026-11-08.
- [x] M3: Batch scan nhiều APK + dashboard tổng hợp (2026-11-08).
- [x] M4: `apiscan dynamic` chạy thật với ZAP + backend InsecureBankv2 (2026-11-08); tự trích tham số HttpClient/Retrofit ✅; còn OkHttp, Burp/Frida.
- [x] M5: `pip install 04_code` → lệnh `apiscan` (pyproject, 1.0.0), `04_code/README.md`, demo `06_slide/demo/` (DEMO.md, demo.sh, báo cáo chạy sẵn) — 2026-11-10; Chương 3 hoàn chỉnh.
