# Notes đọc 3 tài liệu OWASP ưu tiên

> Ngày đọc: 2026-06-26  
> Dùng cho: Chương 1 (Cơ sở lý thuyết) + Chương 3 (thiết kế test case)

---

## [T01] OWASP Mobile Top 10 – 2024

**URL**: https://owasp.org/www-project-mobile-top-10/  
**Release chính thức**: August 2, 2023 (gọi là "2024" nhưng released cuối 2023)

### Điểm khác biệt lớn so với phiên bản 2016

| # | 2016 (cũ) | 2024 (mới) |
|---|-----------|------------|
| M1 | Improper Platform Usage | **Improper Credential Usage** |
| M2 | Insecure Data Storage | **Inadequate Supply Chain Security** ← MỚI |
| M3 | Insecure Communication | **Insecure Authentication/Authorization** |
| M4 | Insecure Authentication | **Insufficient Input/Output Validation** ← MỚI |
| M5 | Insufficient Cryptography | **Insecure Communication** |
| M6 | Insecure Authorization | **Inadequate Privacy Controls** ← MỚI |
| M7 | Client Code Quality | **Insufficient Binary Protections** |
| M8 | Code Tampering | **Security Misconfiguration** |
| M9 | Reverse Engineering | **Insecure Data Storage** |
| M10 | Extraneous Functionality | **Insufficient Cryptography** |

> **Ý nghĩa cho đồ án**: Dùng list 2024 làm framework chính. Khi so sánh với papers cũ (2018–2022) cần note rằng họ dùng list 2016.

### Methodology của OWASP 2024
- Thu thập data từ: HackerOne reports, Ostorlab, CVEs
- Quá trình: Collection (Apr 2023) → Alpha (Jun 2023) → Beta (Jul 2023) → Release (Aug 2023)
- Đánh giá theo: Frequency, Severity, Complexity of exploitation, Prevalence

### Các lỗ hổng KHÔNG vào list (nhưng OWASP ghi chú để theo dõi)
- Data Leakage
- Hardcoded Secrets
- Insecure Access Control
- Path Traversal
- Unprotected Endpoints (Deeplink, Activity, Service)

> **Ghi chú cite**: OWASP Foundation. *OWASP Mobile Top 10 – 2024*. [Online]. Available: https://owasp.org/www-project-mobile-top-10/ [Truy cập: 26/06/2026]

---

## [T02] OWASP API Security Top 10 – 2023

**URL**: https://owasp.org/API-Security/editions/2023/en/0x11-t10/  
**Published**: 2023

### Danh sách đầy đủ với mô tả

| # | Tên | Mô tả ngắn |
|---|-----|-----------|
| API1 | Broken Object Level Authorization (BOLA) | Endpoints dùng object ID không check quyền → IDOR |
| API2 | Broken Authentication | Cơ chế xác thực implement sai → chiếm token, impersonation |
| API3 | Broken Object Property Level Authorization | Kết hợp: Excessive Data Exposure + Mass Assignment (2019) |
| API4 | Unrestricted Resource Consumption | Không rate limiting → DoS, tăng chi phí |
| API5 | Broken Function Level Authorization | Phân quyền theo chức năng sai → truy cập admin function |
| API6 | Unrestricted Access to Sensitive Business Flows | ← **MỚI 2023**: bot/automation exploit business logic |
| API7 | Server Side Request Forgery (SSRF) | API fetch URL user-supplied không validate |
| API8 | Security Misconfiguration | CORS sai, headers thiếu, debug mode bật, default credentials |
| API9 | Improper Inventory Management | Outdated APIs, deprecated endpoints, exposed debug endpoints |
| API10 | Unsafe Consumption of APIs | ← **MỚI 2023**: trust third-party APIs quá mức |

### Điểm quan trọng cho đồ án

**API1 (BOLA)** là lỗ hổng #1 — InsecureBankv2 có nhiều điểm dễ test BOLA:
- `/viewTransaction?txnId=<number>` → thay số để xem giao dịch người khác
- Burp Suite + manual manipulation là cách phát hiện chính; MobSF static KHÔNG detect được

**API3** = combo Excessive Data Exposure + Mass Assignment:
- Static analysis (MobSF/JADX) phát hiện được phần nào qua API response schema
- Dynamic (Burp/ZAP) phát hiện tốt hơn qua response inspection

**API8 (Misconfiguration)** — MobSF static scan phát hiện tốt:
- AndroidManifest: exported=true không bảo vệ
- Debug mode, backup enabled
- Network security config sai

> **Ghi chú cite**: OWASP Foundation. *OWASP API Security Top 10 2023*. [Online]. Available: https://owasp.org/API-Security/ [Truy cập: 26/06/2026]

---

## [T03] OWASP MASTG – InsecureBankv2 (MASTG-APP-0010)

**URL**: https://mas.owasp.org/MASTG/apps/android/MASTG-APP-0010/

### MASTG là gì?
Mobile Application Security Testing Guide — tài liệu kỹ thuật đầy đủ nhất về cách test bảo mật mobile app. Bao gồm:
- **MASVS** (Mobile Application Security Verification Standard) — tiêu chí kiểm tra
- **MASTG** — hướng dẫn test từng tiêu chí
- **MASWE** (Mobile Application Security Weakness Enumeration) — danh mục điểm yếu

### MASVS Categories (liên quan đến đồ án)
| Category | MASVS | Liên quan lỗ hổng |
|----------|-------|------------------|
| MASVS-STORAGE | Storage-1, 2 | M9 Insecure Data Storage |
| MASVS-CRYPTO | Crypto-1, 2 | M10 Insufficient Cryptography |
| MASVS-AUTH | Auth-1, 2, 3 | M3 Insecure Auth, API2 |
| MASVS-NETWORK | Network-1, 2 | M5 Insecure Communication |
| MASVS-PLATFORM | Platform-1, 2, 3 | M1, M8 |
| MASVS-CODE | Code-1, 2, 3, 4 | M7, M4 |
| MASVS-RESILIENCE | Resilience-1, 2, 3, 4 | Binary protection, anti-tampering |

### InsecureBankv2 trong MASTG
- **App ID**: MASTG-APP-0010
- **Status**: Official reference app trong OWASP MASTG
- **Ý nghĩa**: Khi cite lý do chọn InsecureBankv2, có thể dẫn nguồn OWASP MASTG

> **Ghi chú cite**: OWASP Foundation. *Mobile Application Security Testing Guide (MASTG)*. [Online]. Available: https://mas.owasp.org/ [Truy cập: 26/06/2026]

---

## Mapping: OWASP Categories ↔ Tools ↔ InsecureBankv2

| Lỗ hổng | OWASP Mobile | OWASP API | Có trong InsecureBankv2? | Tool phát hiện tốt nhất |
|---------|-------------|-----------|------------------------|------------------------|
| Hardcoded credentials | M1 | - | ✅ hardcoded secret key | MobSF static, JADX |
| Insecure Communication | M5 | - | ✅ HTTP cleartext | Burp Suite, ZAP |
| SSL Pinning bypass | M5 | - | ✅ không có pinning | Frida/objection |
| Insecure Data Storage | M9 | - | ✅ SharedPreferences plaintext | MobSF dynamic, Frida |
| Broken Auth | M3 | API2 | ✅ weak JWT, no session timeout | Burp Suite |
| BOLA/IDOR | - | API1 | ✅ /viewTransaction | Burp Suite manual |
| Security Misconfiguration | M8 | API8 | ✅ backup enabled, exported activities | MobSF static |
| Improper Crypto | M10 | - | ✅ DES encryption (weak) | MobSF static, JADX |
| Debug endpoints | - | API9 | ✅ /devlogin endpoint | Burp Suite, MobSF |

---

## Phát hiện quan trọng: Giới hạn của Static Analysis

Từ việc đọc OWASP API Security Top 10, rút ra điều này cho **Chương 5 (Thảo luận)**:

- **API1 (BOLA)** — **không thể detect bằng static analysis** vì lỗi nằm ở server-side authorization logic, không phải code client. Chỉ dynamic testing (Burp) mới phát hiện được.
- **API4 (Rate limiting)** — tương tự, chỉ detect được khi gửi requests thật.
- **API6 (Business flow abuse)** — cần manual testing, không tool nào tự động detect tốt.

> **Đây là contribution của đồ án**: chứng minh static analysis (MobSF) không đủ, cần kết hợp dynamic.

---

## Các câu trích dẫn có thể dùng trong luận văn

1. *"Broken Object Level Authorization (BOLA) — APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues."* — OWASP API Security Top 10 2023

2. *"Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or to exploit implementation flaws to assume other user's identities temporarily or permanently."* — OWASP API Security Top 10 2023, API2

3. Về Insecure Communication: *"Most modern mobile applications exchange data with one or more remote servers. When the data transmission takes place, it typically goes through the mobile device's carrier network and the internet, a threat agent listening on the wire can intercept and modify the data if it transmitted in plaintext."* — OWASP Mobile Top 10 2024, M5

4. Về method: *"To achieve [the Top 10 list], we collect data from various sources such as incident reports, vulnerability databases, and security assessments, analyze the data, evaluate the sources for reliability and consistency, prioritize the vulnerabilities based on their impact and likelihood of occurrence."* — OWASP Mobile Top 10 Methodology
