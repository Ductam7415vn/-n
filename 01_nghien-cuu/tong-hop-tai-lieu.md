# Tổng hợp tài liệu tham khảo — Đồ án bảo mật API Android

> Cập nhật: 2026-06-26 | Tổng: 18 tài liệu

---

## NHÓM 1: Tiêu chuẩn & Framework chuẩn mực (OWASP)

Đây là nhóm **bắt buộc** phải đọc và trích dẫn — định nghĩa chuẩn về các lỗ hổng.

### [T01] OWASP Mobile Top 10 – 2024
- **Nguồn**: https://owasp.org/www-project-mobile-top-10/
- **Dạng**: Official documentation
- **Dùng cho**: Chương 1 — định nghĩa 10 lỗ hổng Mobile, mapping sang test case
- **Ghi chú**: Bản 2024 là cập nhật lớn đầu tiên kể từ 2016. M1 đổi thành "Improper Credential Usage", bổ sung M2 "Inadequate Supply Chain Security". **Phải đọc toàn bộ.**
- **Cite**: OWASP Foundation. *OWASP Mobile Top 10 – 2024*. Online: https://owasp.org/www-project-mobile-top-10/

### [T02] OWASP API Security Top 10 – 2023
- **Nguồn**: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- **Dạng**: Official documentation
- **Dùng cho**: Chương 1 — định nghĩa API1 (BOLA), API2 (Broken Auth), API8 (Misconfiguration)...
- **Ghi chú**: Tách biệt với Mobile Top 10 — focus vào API endpoint, không phải app
- **Cite**: OWASP Foundation. *OWASP API Security Top 10 – 2023*. Online: https://owasp.org/API-Security/

### [T03] OWASP Mobile Application Security Testing Guide (MASTG)
- **Nguồn**: https://mas.owasp.org/MASTG/ và https://mas.owasp.org/MASTG/apps/android/MASTG-APP-0010/
- **Dạng**: Official guide + test cases
- **Dùng cho**: Chương 1 (phương pháp), Chương 3 (test case design)
- **Ghi chú**: InsecureBankv2 được OWASP MASTG liệt kê chính thức là reference app — **đây là lý lẽ mạnh để cite lý do chọn target app**
- **Cite**: OWASP Foundation. *Mobile Application Security Testing Guide (MASTG)*. Online: https://mas.owasp.org/

---

## NHÓM 2: Papers về MobSF

Nhóm **quan trọng nhất** vì MobSF là tool chính trong đồ án.

### [T04] Android Apps Vulnerability Detection with Static and Dynamic Analysis Approach using MOBSF ⭐
- **Nguồn**: https://www.researchgate.net/publication/381476781
- **Năm**: 2024
- **Dạng**: Research paper (ResearchGate)
- **Nội dung**: Dùng MobSF phân tích tĩnh + động trên nhiều app Android; kết quả static analysis phát hiện được weak crypto, hardcoded secrets, nguy hiểm permissions; dynamic analysis phát hiện SSL issues. True positive rate lên đến 97%.
- **Dùng cho**: Chương 2 (MobSF), Chương 4 (so sánh kết quả)
- **Cite**: (cần lấy tên tác giả đầy đủ từ ResearchGate)

### [T05] An Android Applications Vulnerability Analysis Using MobSF ⭐
- **Nguồn**: https://ieeexplore.ieee.org/document/10581312/
- **Năm**: 2024
- **Dạng**: IEEE Conference Publication — **nguồn uy tín nhất**
- **Nội dung**: Phân tích lỗ hổng app Android bằng MobSF; kết quả phát hiện Janus vulnerability, SQL Injection, padding oracle attack qua static; dynamic phát hiện thiếu root detection
- **Dùng cho**: Chương 2 (MobSF effectiveness), Chương 4
- **Cite**: Lấy từ IEEE Xplore — có DOI chính xác

### [T06] Static Analysis-Based Security Enhancement for Mobile Applications Using MOBSF
- **Nguồn**: https://jurnal.polibatam.ac.id/index.php/JAIC/article/view/9525 và https://www.researchgate.net/publication/395224700
- **Năm**: 2024–2025
- **Dạng**: Journal paper (Journal of Applied Informatics and Computing)
- **Nội dung**: Dùng MobSF static scan, cải thiện security score từ 43/100 lên 67/100 sau khi áp dụng các đề xuất. Phát hiện: debug certificate, debug mode bật, minSdkVersion thấp, exported components không bảo vệ.
- **Dùng cho**: Chương 2 (Output Quality của MobSF), Chương 4

### [T07] The Application of MobSF and MASTG to Ensure Security in Mobile Commerce Applications
- **Nguồn**: https://jsisfotek.org/index.php/JSisfotek/article/view/231
- **Năm**: 2023
- **Dạng**: Journal paper (Jurnal Sistim Informasi dan Teknologi)
- **Nội dung**: Áp dụng MobSF + OWASP MASTG để kiểm tra bảo mật app thương mại điện tử; kết hợp static + dynamic; network monitoring bằng tcpdump và Wireshark
- **Dùng cho**: Chương 2 (workflow kết hợp tools), Chương 3 (phương pháp)

### [T08] Malware Detection and Analysis in Android Applications with MobSF Using Permission-Based Approach
- **Nguồn**: https://link.springer.com/chapter/10.1007/978-981-96-0143-1_11
- **Năm**: 2024–2025
- **Dạng**: Springer book chapter — **nguồn uy tín**
- **Nội dung**: Phân tích malware Android dùng MobSF theo hướng permission-based; đánh giá nguy cơ từ permission groups
- **Dùng cho**: Chương 2 (MobSF static analysis depth)

---

## NHÓM 3: Papers về Dynamic Analysis & Frida/SSL Pinning

### [T09] Developing a Framework for Enhancing Security Testing of Android Applications ⭐
- **Nguồn**: https://www.researchgate.net/publication/383621466
- **Năm**: 2024
- **Dạng**: Research paper
- **Nội dung**: Đề xuất framework kết hợp: QARK (static) + Drozer (dynamic) + SSL pinning bypass; map với OWASP Mobile Top 10; **gần nhất với hướng đồ án này**
- **Dùng cho**: Chương 1 (related work), Chương 5 (đề xuất quy trình)
- **Ghi chú**: Đây là paper gần nhất với scope của đồ án — phải đọc kỹ

### [T10] A Framework to Secure the Development and Auditing of SSL Pinning in Mobile Applications
- **Nguồn**: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7514482/
- **Năm**: 2020
- **Dạng**: Journal paper (PMC/NCBI) — peer-reviewed
- **Nội dung**: Framework đảm bảo SSL Pinning đúng cách; phân tích các kỹ thuật bypass; liên quan đến vai trò của Frida/objection trong testing
- **Dùng cho**: Chương 1 (SSL Pinning lý thuyết), Chương 2 (Frida)

### [T11] Four Ways to Bypass Android SSL Verification and Certificate Pinning
- **Nguồn**: https://www.researchgate.net/publication/347893088
- **Dạng**: Research paper
- **Nội dung**: Mô tả 4 kỹ thuật bypass SSL pinning trên Android; phân tích khi nào dùng kỹ thuật nào
- **Dùng cho**: Chương 2 (Frida/objection), Chương 4 (dynamic analysis với SSL bypass)

### [T12] Detection of SSL/TLS Implementation Errors in Android Applications
- **Nguồn**: https://www.researchgate.net/publication/352289778
- **Năm**: 2021
- **Dạng**: Research paper
- **Nội dung**: Tự động phát hiện lỗi SSL/TLS trong app Android; liên quan đến M3 (Insecure Communication)
- **Dùng cho**: Chương 1 (M3 lý thuyết)

---

## NHÓM 4: Papers về Vulnerability Assessment & Benchmarking

### [T13] Vulnerability Assessment of Android Applications Through Drozer and Static Code Analysis Integration
- **Nguồn**: https://www.researchgate.net/publication/392388407
- **Năm**: 2025
- **Dạng**: Research paper
- **Nội dung**: Kết hợp Drozer (dynamic) + static code analysis; đánh giá lỗ hổng trên nhiều app; phương pháp tương tự đồ án nhưng không có MobSF
- **Dùng cho**: Chương 1 (related work), Chương 2 (Drozer mention)

### [T14] Are Free Android App Security Analysis Tools Effective in Detecting Known Vulnerabilities? ⭐
- **Nguồn**: https://arxiv.org/pdf/1806.09059
- **Năm**: 2018
- **Dạng**: arXiv paper
- **Nội dung**: Đánh giá hiệu quả của các tool miễn phí (FlowDroid, DroidSafe, Amandroid...) trong phát hiện lỗ hổng đã biết; **câu hỏi nghiên cứu gần nhất với đồ án này**
- **Dùng cho**: Chương 1 (related work — so sánh hướng nghiên cứu)
- **Ghi chú**: Dù cũ (2018) nhưng là foundation paper cho hướng nghiên cứu này

### [T15] Assessing the Capability of Android Dynamic Analysis Tools to Combat Anti-Runtime Analysis Techniques
- **Nguồn**: https://arxiv.org/pdf/2512.12551
- **Năm**: 2024
- **Dạng**: arXiv paper
- **Nội dung**: Đánh giá các tool dynamic analysis trước các kỹ thuật anti-analysis; liên quan đến limitation của Frida/MobSF dynamic
- **Dùng cho**: Chương 2 (hạn chế của tools), Chương 5

### [T16] Ghera: A Repository of Android App Vulnerability Benchmarks
- **Nguồn**: https://arxiv.org/pdf/1708.02380
- **Năm**: 2017
- **Dạng**: arXiv paper
- **Nội dung**: Repository benchmark gồm 25 lỗ hổng Android đã biết trong apps thật và lean apps; phương pháp benchmark tham khảo cho thiết kế test case
- **Dùng cho**: Chương 3 (phương pháp thiết kế test case — benchmark framework)

---

## NHÓM 5: Tài liệu kỹ thuật & Tools

### [T17] InsecureBankv2 — Dinesh Shetty
- **Nguồn**: https://github.com/dineshshetty/Android-InsecureBankv2
- **Năm**: 2023
- **Ghi chú**: Target app chính. Documented 25+ lỗ hổng. OWASP MASTG reference app.
- **Cite**: Dinesh Shetty. *Android-InsecureBankv2*. GitHub, 2023. Online: https://github.com/dineshshetty/Android-InsecureBankv2

### [T18] InsecureBankV2 — Pentest Report (pedro-coelho-dr)
- **Nguồn**: https://github.com/pedro-coelho-dr/insecurebankv2-android-security-report
- **Dạng**: Community pentest report
- **Ghi chú**: Report chi tiết các lỗ hổng trong InsecureBankv2 — **đọc để biết trước kết quả kỳ vọng khi test**

---

## Thứ tự đọc đề xuất

### Ưu tiên 1 — Đọc trước khi viết Chương 1 (cần thiết):
1. [T01] OWASP Mobile Top 10 2024 — đọc toàn bộ
2. [T02] OWASP API Security Top 10 2023 — đọc toàn bộ
3. [T03] OWASP MASTG — đọc phần Android + InsecureBankv2

### Ưu tiên 2 — Đọc trước khi viết Chương 2:
4. [T04] MobSF paper 2024 (ResearchGate)
5. [T05] MobSF paper IEEE 2024 — **quan trọng nhất vì IEEE**
6. [T09] Framework kết hợp tools 2024
7. [T14] Free tools effectiveness (2018) — context lịch sử

### Ưu tiên 3 — Đọc khi viết Chương 3+4:
8. [T16] Ghera benchmark — phương pháp thiết kế test case
9. [T11] SSL bypass techniques
10. [T15] Dynamic analysis limitations

---

## Lỗ hổng trong tài liệu hiện tại — CẦN TÌM THÊM

- [ ] Paper so sánh trực tiếp Burp Suite vs OWASP ZAP trên Android (chưa tìm được peer-reviewed)
- [ ] Paper về BOLA/IDOR detection trên Android API cụ thể
- [ ] Paper tiếng Việt từ các tạp chí trong nước (để show tình hình nghiên cứu Việt Nam)
- [ ] Thống kê số liệu về Android market share từ nguồn học thuật (hiện mới có Statista)

---

## Ghi chú khi cite

- Tài liệu từ **IEEE Xplore** và **Springer** → uy tín nhất, cite trước
- Tài liệu từ **arXiv** → chưa peer-reviewed nhưng chấp nhận được nếu không có nguồn khác
- **Tránh cite** blog, Medium, website thương mại trong luận văn chính
- URL trong cite cần kèm "[Truy cập: ngày/tháng/năm]" theo chuẩn IEEE
