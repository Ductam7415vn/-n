# Plan tối ưu Base/Harness cho đồ án

_Ngày: 2026-07-02_

## 1. Audit hiện trạng base

| Thành phần | Trước | Sau khi tối ưu |
|---|---|---|
| Memory (`CLAUDE.md`) | Có, tốt nhưng thiếu quy ước làm việc | ✅ Thêm mục "Quy ước làm việc", cảnh báo skill nhiễu, cập nhật log 2026-07-02 |
| Skill `android-api-security` | Có nhưng `SKILL.md` sai đánh số OWASP (2016), nhắc Genymotion, gợi ý sai target app | ⚠️ Đã tạo bản sửa `SKILL_corrected.md` — **cần bạn dán vào Settings** (cache read-only) |
| `.claude/settings.json` | Chưa có | ✅ Đã tạo (permissions + hooks) |
| Hooks | Chưa có | ✅ SessionStart (in TODO + nhắc quy ước) + Stop (nhắc cập nhật memory) |
| Skill nhiễu (dự án khác) | ~15 skill lạ bật chung | ⚠️ **Cần bạn tắt** trong Settings > Capabilities |

## 2. Lỗi cụ thể đã phát hiện & xử lý

1. **Sai chuẩn OWASP trong `SKILL.md`**: bảng "ưu tiên lỗ hổng" dùng đánh số Mobile **2016** (M3=Insecure Communication, M4=Insecure Auth, M1=Improper Platform Usage) trong khi `references/vulnerabilities.md` và `CLAUDE.md` đã dùng **2024** (M5=Insecure Comm, M3=Insecure Auth, M1=Improper Credential). → Đã sửa trong bản mới.
2. **Genymotion**: `SKILL.md` viết "AVD / Genymotion" nhưng `CLAUDE.md` đã chốt KHÔNG dùng Genymotion (Apple Silicon). → Đã bỏ.
3. **Target app**: `SKILL.md` khuyến nghị "InsecureBankv2 hoặc Damn Vulnerable Bank" nhưng đồ án đã chốt InsecureBankv2. → Đã đồng bộ.

## 3. Việc bạn cần làm tay (2 việc)

### 3.1. Cập nhật skill android-api-security
File cache của skill là read-only nên không sửa trực tiếp được. Cách làm:
1. Mở **Settings > Capabilities** (hoặc thư mục skill gốc của bạn).
2. Mở `android-api-security/SKILL.md`.
3. Thay toàn bộ nội dung bằng file `SKILL_corrected.md` mình vừa tạo.

### 3.2. Tắt các skill của dự án khác (giảm nhiễu)
Trong Settings > Capabilities, tắt các skill KHÔNG liên quan đồ án:
`analytics-audit`, `arch-audit`, `ads-implementation`, `module-refactor`, `firebase-crash-analyzer`, `hema-analyzer-loop`, `tcbs-backend-ui`, `udemy-video-summarizer`, `linkedin-post`.
→ Giữ lại: `android-api-security`, `srs-writer`, `docx`, `pptx`, `canvas-design`, `data:*`, `deep-research`, `pdf`, `xlsx`.

## 4. Roadmap phát triển đồ án (theo TODO trong CLAUDE.md)

**Phase 1 — Dựng lab (tuần này)**
- Cài Docker Desktop + Android Studio; tạo AVD ARM64 Android 13.
- Cài InsecureBankv2 APK + chạy backend Flask (port 8888), verify login.

**Phase 2 — Cài tool**
- MobSF (Docker) → static scan APK đầu tiên.
- Burp Suite → cấu hình proxy intercept AVD.
- Frida + objection → push frida-server, test bypass SSL pinning.

**Phase 3 — Benchmark**
- Thiết kế test case matrix (tool × 10 lỗ hổng ưu tiên) trong `03_benchmark/so-sanh-tool/`.
- Chạy từng tool, lưu raw output theo `03_benchmark/ket-qua-test/<tool>/`.
- Tính Detection Rate, False Positive, Coverage... theo 7 tiêu chí.

**Phase 4 — Viết & bảo vệ**
- Viết luận văn (`docx` + `references/thesis_structure.md`) trong `05_bao-cao/`.
- Visualize kết quả (`data:create-viz`), làm slide (`pptx`) trong `06_slide/`.

## 5. Quy ước duy trì base
- Sau mỗi quyết định lớn → thêm dòng vào "Ghi chú / Quyết định" trong CLAUDE.md.
- Hoàn thành 1 mục → tick "TODO tiếp theo".
- Khi đổi hướng/tool → cập nhật cả CLAUDE.md và SKILL.md để tránh mâu thuẫn.
