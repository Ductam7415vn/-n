# apiscan

Công cụ phát hiện dấu hiệu lỗ hổng bảo mật trong tệp APK Android bằng phân tích tĩnh. Một lệnh nhận tệp APK và xuất báo
cáo HTML + JSON: cảnh báo gắn nhãn OWASP Mobile Top 10 – 2024, **độ tin cậy** của từng cảnh báo, **bản đồ endpoint**
API trích từ mã và **bề mặt tiếp nhận intent** (thành phần exported cần rà soát).

Công cụ chỉ đọc tệp: không cài, không chạy ứng dụng, không gửi yêu cầu tới máy chủ của ứng dụng. Riêng lệnh `dynamic`
gửi yêu cầu qua OWASP ZAP và chỉ chạy với máy chủ được phép (xem mục Quét động có dẫn đường).

## Cài đặt

Cần:
- Python ≥ 3.10
- [apktool](https://apktool.org) và [JADX](https://github.com/skylot/jadx) trong `PATH` (cả hai cần Java).
  Trên macOS: `brew install apktool jadx`.

```bash
cd 04_code
pip install .            # cài lệnh `apiscan`
pip install ".[config]"  # kèm PyYAML để đọc tệp cấu hình --config
apiscan --version
```

Không cài cũng chạy được: `python3 04_code/scripts/apiscan.py <lệnh> …` (các ví dụ dưới đây dùng được cả hai cách).

## Sử dụng

### Quét một APK

```bash
apiscan scan app.apk                              # báo cáo vào ./apiscan-report/<package>/
apiscan scan app.apk -o out/ --min-confidence medium
apiscan scan app.apk --app-pkg com.example.app --app-pkg com.example.core
```

Các bước: tính SHA-256 → giải nén bằng apktool và dịch ngược bằng JADX vào thư mục làm việc (mặc định
`~/.cache/apiscan/<sha256>`, đổi bằng `--work-dir`) → tự suy phạm vi mã của ứng dụng từ Manifest → chạy bộ luật → ghi
`report.html` và `report.json`. Lần quét sau của cùng một APK dùng lại kết quả giải nén (`--force-decompile` để làm lại).

Thời gian đo trên MacBook Apple Silicon (2026-11-10): InsecureBankv2 18,6 giây lần đầu, gần hết là thời gian của JADX;
0,2 giây khi đã có kết quả giải nén. NewPipe 0.29.1 khoảng 45 giây lần đầu.

**Phạm vi mã.** Công cụ chỉ quét mã của ứng dụng, không quét thư viện bên thứ ba. Phạm vi được tự suy từ package của
các thành phần khai báo trong Manifest. Nếu mã lõi nằm ở namespace không có thành phần nào trong Manifest, thêm bằng
`--app-pkg` (lặp lại được).

**Ngưỡng tin cậy khuyến nghị: `--min-confidence medium`.** Trên 19 ứng dụng thật của phần đánh giá, ngưỡng này bớt 58%
số cảnh báo và chỉ mất 3/57 cảnh báo đúng.

### Quét nhiều APK

```bash
apiscan batch apks/ -o out/            # thư mục hoặc danh sách tệp .apk
```

Xuất báo cáo riêng cho từng ứng dụng, cùng `out/index.html` và `out/summary.csv`/`summary.json`: số cảnh báo theo tầng
tin cậy, số endpoint, thời gian, tỉ lệ ứng dụng có cảnh báo theo từng luật. Một APK lỗi không làm dừng cả lượt.

### Tệp cấu hình và bỏ qua cảnh báo

```bash
apiscan scan app.apk --config apiscan.yml
apiscan baseline out/app/report.json -o apiscan.yml   # bỏ qua mọi cảnh báo hiện có
```

```yaml
min_confidence: medium
rules:
  disable: [CRY-HASH]
suppress:
  - rule: CFG-EXPORT
    evidence: "*.ShareActivity*"
    reason: "Nhận intent SEND là chức năng chính, đã rà cách xử lý dữ liệu đầu vào"
  - id: 0123456789ab              # dấu vân tay 12 ký tự in trong báo cáo
    reason: "Khoá công khai của Google Play, không phải bí mật"
```

Mỗi mục bỏ qua bắt buộc có `reason`. Cảnh báo bị bỏ qua vẫn được liệt kê kèm lý do trong báo cáo; mục không khớp cảnh
báo nào được báo ra để phát hiện mục lỗi thời. Mẫu đầy đủ: `scripts/apiscan.example.yml`.

### Quét động có dẫn đường

```bash
apiscan dynamic out/app/report.json --target http://127.0.0.1:8888 --zap-key <khoá API của ZAP>
```

Dùng bản đồ endpoint và các yêu cầu HTTP trích từ mã (phương thức và tên tham số của Apache HttpClient, Retrofit) làm
điểm khởi đầu cho OWASP ZAP, rồi gộp kết quả với báo cáo tĩnh thành `dynamic/merged.html`. **Cổng an toàn:** mục tiêu
phải là loopback hoặc mạng riêng; với địa chỉ khác phải truyền `--authorization <tệp văn bản cho phép>`, SHA-256 của tệp
được ghi vào báo cáo. Yêu cầu viết tay (ví dụ có tài khoản hợp lệ) truyền qua `--seed-requests`.

### Mã thoát

| Mã | Ý nghĩa |
|---|---|
| 0 | Chạy xong, có hay không có cảnh báo |
| 1 | `batch`: có ít nhất một APK lỗi |
| 2 | Lỗi đầu vào: không thấy tệp, thiếu apktool/JADX, tệp cấu hình sai |

## Đọc báo cáo

| Trường | Ý nghĩa |
|---|---|
| Mức nghiêm trọng | Hậu quả nếu cảnh báo đúng |
| Độ tin cậy | Khả năng cảnh báo đúng. **high**: bằng chứng trực tiếp. **medium**: dấu hiệu mạnh, nhưng mã có thể có kiểm tra mà phân tích tĩnh không thấy. **low**: bề mặt rủi ro, tự nó chưa phải lỗ hổng |
| Vị trí, bằng chứng | Tệp:dòng trong mã dịch ngược hoặc Manifest, và đoạn khớp luật |
| Bề mặt tiếp nhận intent | Thành phần exported có lý do chính đáng (LAUNCHER, intent hệ thống, giao thức với ứng dụng khác). Không tính là lỗ hổng, nhưng là nơi cần rà cách xử lý dữ liệu đầu vào |
| Endpoint, yêu cầu HTTP | URL và đường dẫn API trong mã có gọi mạng, kèm phương thức và tên tham số khi trích được |

Thứ tự rà soát đề xuất: high trước, medium sau; low chỉ xem khi cần độ phủ đầy đủ.

## Bộ luật

| Nhóm OWASP Mobile 2024 | Luật |
|---|---|
| M1 – Improper Credential Usage | CRY-KEYLIT, CRY-KEYHARD, KEY-SERVICE |
| M4 – Insufficient Input/Output Validation | WEB-JS, WEB-IFACE |
| M5 – Insecure Communication | NET-CLEAR, NET-NSC, NET-TRUST, NET-SDK, NET-HTTP |
| M8 – Security Misconfiguration | CFG-DEBUG, CFG-BACKUP, CFG-EXPORT, API-HIDDEN |
| M9 – Insecure Data Storage | STO-EXT, STO-PREF-WORLD, LOG-SENS |
| M10 – Insufficient Cryptography | CRY-WEAK, CRY-IV0, CRY-HASH |

Mô tả từng luật, các kỹ thuật giảm báo nhầm và quy tắc chấm độ tin cậy: luận văn, Chương 3, mục 3.2.
`--export-rules v2` bật hai thay đổi thử nghiệm cho CFG-EXPORT (đo ở holdout đợt 10, chưa kết luận); mặc định là v1.

## Giới hạn

- Precision trên ứng dụng chưa dùng để chỉnh luật dao động 2,8–40% tuỳ ứng dụng: cảnh báo là gợi ý cho người rà soát,
  không phải kết luận.
- Luồng dữ liệu chỉ được theo dõi trong một tệp; mã bị R8 đổi tên hoặc dời vào package mặc định có thể bị bỏ sót.
- Không thấy lỗi phía máy chủ và lỗi "vắng mặt cơ chế", ví dụ thiếu certificate pinning.

## Kiểm thử

```bash
python3 -m unittest discover -s 04_code/tests -v
```
