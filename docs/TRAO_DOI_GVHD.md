# Nội dung trao đổi với GVHD (TS. Phạm Duy Trung) về đổi trọng tâm

> Mục đích: xin ý kiến thầy trước khi chốt đổi hướng, vì khác đề cương và hai phiếu tiến độ đã nộp.
> Dưới đây là bản nháp để bạn tự diễn đạt lại, không gửi nguyên văn.

## Tóm tắt đề xuất

Em xin đề xuất điều chỉnh trọng tâm đồ án: từ *"nghiên cứu, so sánh các công cụ phát hiện lỗ hổng"*
sang *"xây dựng một công cụ phát hiện lỗ hổng bảo mật API/Android, có kiểm chứng độ chính xác và áp
dụng trên ứng dụng thật"*. Tên đề tài đã duyệt ("Nghiên cứu công cụ tự động phát hiện lỗ hổng bảo
mật API của ứng dụng Android") vẫn phù hợp với hướng mới.

## Lý do

1. Trong quá trình thực nghiệm, em đã viết thử một công cụ phân tích tĩnh và chạy thật:
   - Trên ứng dụng có lỗ hổng chủ đích (InsecureBankv2): phát hiện đúng 100% nhóm lỗ hổng tĩnh.
   - Trên một ứng dụng thật mã nguồn mở (NewPipe): độ chính xác (precision) rớt còn khoảng 6% — phần
     lớn cảnh báo là hành vi cố ý, thậm chí công cụ gắn cờ nhầm chính đoạn mã bảo mật tốt.
2. Khoảng cách này cho thấy một vấn đề nghiên cứu cụ thể và có giá trị: **làm sao giảm báo nhầm của
   phân tích tĩnh trên ứng dụng thật**. Giải quyết nó bằng cách xây một công cụ biết lọc báo nhầm và
   cho output dùng được sẽ có đóng góp rõ ràng hơn so với chỉ so sánh công cụ.
3. Phần benchmark và thiết kế thực nghiệm đã làm (Chương 1, 2) không bỏ đi — nó trở thành cơ sở để
   chọn kỹ thuật và để kiểm chứng độ chính xác của công cụ.

## Em dự kiến nộp những gì

- Công cụ `apiscan` chạy được (một lệnh → báo cáo lỗ hổng + bản đồ endpoint + điểm tin cậy).
- Số liệu kiểm chứng: recall trên app có đáp án, precision trên ≥ 3 app thật mã nguồn mở.
- Luận văn 3 chương + slide; Chương 3 trình bày công cụ, kết quả, và quy trình đề xuất.

## Câu hỏi xin ý kiến thầy

1. Thầy thấy hướng "xây công cụ + kiểm chứng" có phù hợp mức đồ án tốt nghiệp không?
2. Có cần cập nhật lại đề cương/tên đề tài trên hệ thống không?
3. Về phần phân tích động: em chỉ thực hiện trên app có chủ đích trong lab và app được phép; thầy có
   lưu ý gì về mặt đạo đức/pháp lý khi nhắc tới ứng dụng thật trong luận văn không?

## Phát hiện phụ cần báo cáo

Khi kiểm chứng, em thấy mô tả lỗ hổng V05 trong tài liệu tham chiếu ghi "DES 56 bit" nhưng mã thật
của InsecureBankv2 dùng AES/CBC với khoá cứng và IV tĩnh. Em sẽ đính chính trong luận văn.
