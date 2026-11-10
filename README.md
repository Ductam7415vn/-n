# apiscan — Đồ án tốt nghiệp

Đồ án tốt nghiệp ngành An toàn thông tin, Học viện Kỹ thuật mật mã: xây dựng và đánh giá **apiscan**, công cụ phân tích
tĩnh tệp APK Android để phát hiện dấu hiệu lỗ hổng bảo mật API, có điểm tin cậy cho từng cảnh báo và bản đồ endpoint.

- Sinh viên: Nguyễn Đức Tâm
- Giáo viên hướng dẫn: TS. Phạm Duy Trung

## Cấu trúc

| Thư mục | Nội dung |
|---|---|
| `04_code/` | Mã nguồn công cụ, bộ test; cài đặt và cách dùng ở [`04_code/README.md`](04_code/README.md) |
| `03_benchmark/` | Số liệu đánh giá: nhãn gán tay (`ground-truth/`), báo cáo quét từng đợt (`ket-qua-test/`), recall trên lỗ hổng đã công bố (`recall_cve/`) |
| `05_bao-cao/` | Luận văn (`DoAnTotNghiep_NguyenDucTam.pdf`/`.docx`), bản thảo Chương 3 và Kết luận dạng Markdown, script ghép |
| `05_bao-cao/bao-cao-thuc-tap/` | Báo cáo thực tập tại Công ty BetaSoft (bản Markdown, `.docx`, hình và minh chứng) |
| `06_slide/` | Phiếu hỏi–đáp bảo vệ, bộ demo (`demo/DEMO.md`, `demo/demo.sh`) |
| `01_nghien-cuu/`, `02_cong-cu/` | Tài liệu nghiên cứu và môi trường ban đầu |
| `docs/` | Sổ tiến độ và lộ trình phát triển công cụ |

## Kết quả chính

- Recall 6/6 trên các lỗ hổng tĩnh của InsecureBankv2, giữ được ở ngưỡng tin cậy ≥ medium.
- Precision trên 19 ứng dụng mã nguồn mở: 17,2% với mọi cảnh báo, 39,1% ở ngưỡng ≥ medium; trên 10 đợt holdout (ứng
  dụng chưa dùng để chỉnh luật) dao động 2,8–40%. Mục tiêu ≥ 50% trên ứng dụng mới không đạt.
- So với MobSF trên cùng nhãn: 17,2% so với 5,0%, tức người kiểm thử đọc ít hơn khoảng 3,6 lần số cảnh báo.

## Đạo đức và ẩn danh

Thực nghiệm chỉ dùng ứng dụng có lỗ hổng có chủ đích (InsecureBankv2) và ứng dụng mã nguồn mở trên F-Droid, chỉ phân tích
tĩnh, không gửi yêu cầu tới máy chủ của bên thứ ba. Một số lỗ hổng tìm được trên ứng dụng thật đang được công bố có trách
nhiệm cho nhà phát triển, nên trong bản công khai này tên thành phần và cách khai thác được thay bằng `[ẩn danh A]`,
`[ẩn danh B]`, `[ẩn danh C]`. Việc thay được áp dụng nhất quán cho cả nhãn và báo cáo quét, nên mọi số liệu tính lại từ
repo vẫn khớp với luận văn. Chi tiết sẽ được bổ sung sau khi bản sửa được phát hành.

Tệp APK và mã dịch ngược không nằm trong repo; nguồn tải và SHA-256 ở `04_code/target-app/APK_SOURCES.md`.
