# KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

## Kết quả đạt được

Đồ án bắt đầu từ việc khảo sát các công cụ tự động phát hiện lỗ hổng bảo mật API của ứng dụng Android. Từ đó, đồ án xây
dựng được một công cụ phân tích tĩnh có đầu ra dùng được, kèm một phương pháp đánh giá công cụ trung thực. Đối chiếu với
các mục tiêu đặt ra trong đề cương, đồ án đạt được các kết quả sau.

**Thứ nhất, về tổng quan và môi trường thực nghiệm.** Chương 1 hệ thống hoá:
- cơ chế giao tiếp API của ứng dụng Android;
- hai bộ tiêu chuẩn OWASP Mobile Top 10 (2024) và OWASP API Security Top 10 (2023);
- ba phương pháp kiểm tra bảo mật;
- bảy công cụ tự động tiêu biểu.

Chương 2 phân tích chi tiết ranh giới năng lực của từng công cụ, xây dựng môi trường thực nghiệm trên máy Apple Silicon và
bộ đáp án 12 lỗ hổng của InsecureBankv2. Khi đối chiếu đáp án với mã nguồn thật, đồ án phát hiện bốn mục mô tả sai,
trong đó mục V05 vốn được mô tả là DES nhưng thực tế là AES/CBC với khoá cứng và IV tĩnh. Các mục này đã được hiệu chỉnh
trước khi dùng đáp án để chấm công cụ.

**Thứ hai, về công cụ.** Công cụ `apiscan` đi từ một tệp APK tới báo cáo HTML/JSON chỉ bằng một lệnh. Công cụ có các đặc
điểm sau:
- Tự giải nén và dịch ngược, rồi tự suy ra phạm vi mã của ứng dụng để tách khỏi mã thư viện.
- Áp dụng 20 luật gắn nhãn OWASP.
- Mỗi cảnh báo có bằng chứng `tệp:dòng`, mức nghiêm trọng và điểm tin cậy.
- Báo cáo kèm bản đồ điểm cuối API và danh sách bề mặt tiếp nhận intent.
- Bảy kỹ thuật giảm báo nhầm theo ngữ cảnh (mục 3.2.3) thay các luật so khớp mẫu thô bằng điều kiện mà một lỗ hổng thật
  phải thoả mãn.
- Công cụ chỉ đọc tệp APK, không cài đặt, không chạy ứng dụng và không gửi yêu cầu tới máy chủ của ứng dụng.
- Thời gian phân tích trung vị là 0,82 giây mỗi ứng dụng.
- Quét hàng loạt nhiều APK kèm trang tổng hợp; cấu hình YAML để tắt luật, đặt ngưỡng và bỏ qua các báo nhầm đã xác
  nhận (kèm lý do, dựa trên dấu vân tay ổn định của cảnh báo).
- Lệnh quét động dẫn đường cho OWASP ZAP bằng bản đồ endpoint tĩnh cùng phương thức và tên tham số tự trích từ mã
  (Apache HttpClient, Retrofit), và gộp kết quả thành báo cáo hợp nhất, có cổng an toàn chỉ cho phép quét máy chủ cục bộ
  hoặc có văn bản cho phép.

**Thứ ba, về kết quả đánh giá định lượng.**
- Công cụ phát hiện đủ 6/6 lỗ hổng tĩnh của InsecureBankv2 ở mọi phiên bản luật, kể cả khi lọc ở ngưỡng tin cậy
  ≥ medium.
- Trên 19 ứng dụng mã nguồn mở thực tế, phiên bản cuối đạt precision 17,2% với mọi cảnh báo, 39,1% ở ngưỡng ≥ medium và
  80,6% ở tầng high.
- Quét động có dẫn đường trên backend InsecureBankv2: không có bản đồ endpoint, ZAP không quét được endpoint API nào; có
  bản đồ và tham số từ phân tích tĩnh, ZAP đưa ra 27 cảnh báo, trong đó có XSS phản xạ ở hai endpoint (ngoài đáp án).
  Khi yêu cầu mẫu do công cụ tự trích từ mã thay cho yêu cầu viết tay, ZAP vẫn tìm ra đúng hai lỗi XSS này (26 cảnh báo).
  Các lỗi nghiệp vụ V07, V08, V09, V12 mà ZAP không tự phát hiện được đều được kiểm chứng thủ công.
- Trên 10 lỗ hổng do GitHub Security Lab công bố ở 5 ứng dụng mã nguồn mở, công cụ phát hiện đúng cơ chế 3/10 (đều là
  provider exported thiếu permission) và trỏ đúng thành phần cho 7/10 còn lại (lỗi logic ở deep link, intent, AIDL); không
  lỗ hổng nào bị bỏ sót hoàn toàn.
- Tầng tin cậy low hoạt động như một bộ lọc nhiễu: bỏ tầng này giảm 58,3% số cảnh báo, trong khi chỉ mất 3/57 lỗ hổng
  thật.
- Đối chứng với MobSF trên cùng tập ứng dụng và cùng định nghĩa nhãn:
  - Trên InsecureBankv2, MobSF ở cấu hình mặc định chỉ đạt 2/6.
  - Precision của MobSF ước lượng 5,0% (khoảng tin cậy 95%: 2,2–11,2%), so với 17,2% của `apiscan` (13,5–21,7%).
  - Số lỗ hổng thật hai công cụ tìm được tương đương, nhưng `apiscan` đưa ra ít cảnh báo hơn khoảng 3,6 lần.

**Thứ tư, về phương pháp và dữ liệu.** Đồ án đóng góp:
- Giao thức đánh giá holdout mười đợt: luật được đóng băng trước khi gặp ứng dụng mới.
- Bộ dữ liệu 608 nhãn đúng/sai có ghi lý do trên 23 ứng dụng, cùng 100 nhãn cho mẫu cảnh báo của MobSF. Bộ dữ liệu tái
  lập được để đánh giá các công cụ khác.

Kết quả quan trọng nhất về phương pháp là precision đo trên tập ứng dụng dùng để chỉnh luật không phản ánh precision trên
ứng dụng mới. Trên tập phát triển, precision ở ngưỡng ≥ medium là 40–63%, trong khi trên mười đợt holdout precision chỉ
dao động 2,8–40% và không hội tụ.

**Thứ năm, về giá trị thực tế.** Khi rà soát cảnh báo của công cụ trên ứng dụng thật, đồ án ghi nhận một số phát hiện bảo
mật:
- Hai lỗ hổng mức nghiêm trọng cao ở thành phần exported không được bảo vệ, đang được công bố có trách nhiệm cho nhà phát
  triển.
- Activity của thư viện cắt ảnh bị exported.
- Công cụ debug lọt vào bản phát hành.
- Khoá API nhúng cứng.

Từ đó, đồ án đề xuất quy trình sử dụng công cụ trong kiểm thử bảo mật API gồm ba bước:
1. Sàng lọc tĩnh tự động bằng `apiscan` ở ngưỡng ≥ medium.
2. Chuyên gia rà soát theo thứ tự tầng tin cậy: high trước, medium sau.
3. Kiểm thử động để xác nhận, chỉ khi có văn bản cho phép của chủ ứng dụng.

## Hạn chế

- **Mục tiêu precision ≥ 50% trên ứng dụng mới không đạt.** Precision trên holdout phụ thuộc mạnh vào miền ứng dụng, vì
  mỗi miền mới sinh ra một lớp báo nhầm mà luật dựa trên mẫu chưa gặp.
- **Kết quả precision phụ thuộc quy ước gán nhãn.** Nếu cấu hình cleartext và tin chứng chỉ do người dùng cài ở cấp toàn
  ứng dụng được coi là hành vi có chủ đích, precision tầng high giảm từ 80,6% xuống 9,7%.
- **Chỉ một người gán nhãn**, chưa đo độ đồng thuận giữa các người gán (bộ phiếu và script tính kappa đã chuẩn bị sẵn).
  Recall trên ứng dụng thật mới đo được trên 10 lỗ hổng đã công bố, thiên về thành phần exported; recall của các luật mật
  mã, lưu trữ, ghi log chưa đo.
- **Lỗi logic ở bề mặt tiếp nhận intent chỉ được chỉ ra, không được cảnh báo**: 7/10 lỗ hổng đã công bố thuộc nhóm này.
- **Phân tích còn hạn chế ở ba điểm.** Luồng dữ liệu chỉ được phân tích trong phạm vi một tệp. Phạm vi mã chưa nhận ra mã
  ứng dụng bị R8 dời vào package mặc định; đối chứng với MobSF đã chỉ ra một lỗ hổng thật bị bỏ sót vì lý do này. Công cụ
  cũng không phát hiện được lỗ hổng phía máy chủ (V08, V09, V12) hay lỗi "vắng mặt cơ chế" như thiếu certificate pinning
  (V03).
- **Phần benchmark động chưa thực hiện.** Khi đồ án chuyển trọng tâm sang xây dựng công cụ, phần benchmark bảy công cụ
  theo ma trận kiểm thử ở Chương 2 chỉ được thực hiện với nhóm công cụ tĩnh: JADX, apktool và phân tích tĩnh của MobSF.
  Các ca kiểm thử động với Burp Suite và Frida chưa được chạy. Phần ZAP đã chạy qua lệnh `dynamic` của `apiscan` trên
  backend InsecureBankv2 (mục 3.7), nhưng chỉ trên một ứng dụng có chủ đích với cấu hình mặc định.

## Hướng phát triển

- Mở rộng phân tích luồng dữ liệu xuyên lớp để theo dõi khoá, mật khẩu và URL được khai báo ở lớp này nhưng dùng ở lớp
  khác.
- Kết luận hai quy tắc CFG-EXPORT mà phép đo recall chỉ ra. Holdout đợt 10 chưa đủ cảnh báo để kết luận. Cần một đợt
  holdout có nhiều thành phần exported hơn, và không coi action thuộc namespace thư viện (`androidx.`, `org.unifiedpush.`)
  là action tuỳ biến của ứng dụng.
- Cải tiến bộ suy phạm vi mã cho hai trường hợp: namespace không có thành phần khai báo trong Manifest, và mã bị R8 dời
  vào package mặc định.
- Mở rộng bộ trích yêu cầu HTTP sang OkHttp và mã đã bị R8 làm rối, và trích cả giá trị tham số khi có thể. Thực hiện
  phần Burp Suite, Frida của ma trận Chương 2. Sau đó đưa kiểm thử động vào quy trình, chỉ áp dụng cho ứng dụng có sự cho
  phép của chủ sở hữu.
- Mời thêm người gán nhãn độc lập để đo độ đồng thuận, và mở rộng tập holdout sang các miền ứng dụng chưa có (ngân hàng,
  thương mại điện tử) với ứng dụng được phép phân tích.
