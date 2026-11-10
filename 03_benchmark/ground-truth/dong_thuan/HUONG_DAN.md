# Hướng dẫn gán nhãn độc lập (người gán thứ hai)

Bạn nhận 80 cảnh báo do công cụ phân tích tĩnh `apiscan` đưa ra trên các ứng dụng Android mã nguồn mở. Với mỗi cảnh báo,
hãy quyết định nó có chỉ đúng một **điểm yếu bảo mật có thật** hay không. Làm độc lập: không hỏi người gán thứ nhất, không
mở `dap_an_an.json`.

## Tài liệu nhận được
- `phieu_gan_nhan.html` — từng cảnh báo kèm vị trí, bằng chứng và đoạn mã ngữ cảnh (dòng có dấu `>` là dòng bị cảnh báo).
- `phieu_gan_nhan.csv` — điền vào các cột trống, mở bằng Excel/Google Sheets, lưu lại dạng CSV UTF-8.
- Nếu cần xem thêm mã: APK gốc tải từ F-Droid theo tên ứng dụng và phiên bản trong phiếu, dịch ngược bằng JADX.

## Các cột cần điền
| Cột | Giá trị | Ý nghĩa |
|---|---|---|
| `label` | `TP` hoặc `FP` | TP: cảnh báo chỉ đúng một điểm yếu có thật. FP: không phải điểm yếu. |
| `fp_type` | `pattern` / `intended` (chỉ khi FP) | pattern: luật khớp mẫu sai (vd URI namespace bị coi là kết nối mạng). intended: hành vi cố ý hoặc bắt buộc của app (vd WebView đăng nhập OAuth cần JavaScript). |
| `borderline` | `x` nếu phân vân | Đánh dấu nhận định có thể tranh luận. |
| `reason` | một câu | Lý do ngắn, dựa trên mã/manifest. |

## Quy ước (giữ giống người gán thứ nhất)
- Mật mã do giao thức quy định (CRAM-MD5, APOP, giao thức thiết bị đeo, định dạng tệp của app khác) → FP `intended`.
- Cho phép cleartext hoặc tin CA do người dùng cài ở cấp **toàn ứng dụng** → TP (điểm yếu có thật dù có chủ đích).
- `allowBackup="true"` không có quy tắc loại trừ dữ liệu nhạy cảm → TP mức nhẹ.
- Thành phần exported: TP nếu ứng dụng khác gọi được và đi tới chức năng/dữ liệu cần bảo vệ; FP nếu chỉ mở giao diện
  công khai hoặc mã có kiểm tra bên gọi.
- Chuỗi trông như khoá nhưng là tên cột, khoá SharedPreferences, nhãn giao diện → FP `pattern`.
- Chỉ đánh giá điều cảnh báo nói; lỗ hổng khác bạn tình cờ thấy thì ghi vào `reason`, không đổi nhãn.

Thời gian dự kiến: 2–3 giờ.
