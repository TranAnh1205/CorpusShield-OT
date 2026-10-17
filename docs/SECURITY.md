# Mô hình đe dọa và giới hạn

## Quyền của kẻ tấn công

Kẻ tấn công có thể thêm tài liệu vào nguồn nạp và biết truy vấn đánh giá gốc. Ở điều kiện mạnh hơn, họ có khóa HMAC và ký được tài liệu độc. Benchmark không cho họ sửa corpus nguồn, snapshot đã duyệt, mã chạy hoặc kết quả sau khi truy xuất. Điều kiện phát lại chữ ký dùng chữ ký hợp lệ của tài liệu mục tiêu trên nội dung độc khác và phải bị từ chối.

HMAC có tác dụng khi khóa chưa lộ: chữ ký giả bị từ chối. Nếu khóa lộ, HMAC không phân biệt tài liệu sạch và tài liệu độc đã được ký. Snapshot chỉ có tác dụng nếu được tạo từ dữ liệu sạch đã rà soát **trước** khi nhận tài liệu của kẻ tấn công, được lưu trong miền quyền riêng, và mọi thay đổi hợp lệ phải qua phê duyệt. Nếu snapshot bị sửa hoặc được tạo từ corpus đã nhiễm độc, hàng rào này không còn ý nghĩa.

## Phạm vi bảo đảm

Thí nghiệm chỉ kiểm tra cổng nạp và mức phơi nhiễm top-k. Nó không xác thực nội dung của advisory, không bảo đảm KEV chính xác, không phát hiện prompt injection trong tài liệu đã duyệt và không bảo đảm câu trả lời LLM an toàn. HMAC là mô phỏng trong cùng tiến trình với khóa cố định ở benchmark để tái lập, không phải quản lý khóa dùng trong sản xuất. Dự án chưa triển khai luồng duyệt snapshot, phân quyền, lưu trữ khóa, nhật ký kiểm toán hay dịch vụ RAG hoàn chỉnh.

Đã bổ sung chế độ `query-blind`: chỉ dùng tiêu đề mục tiêu công khai, không sử dụng hai truy vấn đánh giá. Đây vẫn là payload theo mẫu, chưa phải tấn công ngữ nghĩa thích nghi. Snapshot có thể đọc từ tệp và kiểm tra SHA-256 do người vận hành cung cấp từ nơi tin cậy; mã không tự tạo miền quyền riêng, quản lý phiên bản hay chống rollback.

Luồng mạng giới hạn dung lượng, xác minh hash trước khi xuất bản tệp, chỉ dùng HTTPS với nguồn dữ liệu và không theo redirect. Endpoint LLM cho phép HTTP loopback được người vận hành chọn. Cấu hình endpoint là đầu vào tin cậy; đây không phải bộ lọc SSRF cho dịch vụ nhận URL từ người dùng không tin cậy. KEV được đọc và xác minh trên cùng vùng byte; manifest CSAF có SHA-256 ghim trong mã. Git SHA-1 chỉ kiểm tra danh tính blob theo manifest, không được coi là chữ ký nguồn.

Snapshot được kiểm tra cấu trúc và sao chép trước khi duyệt đầu vào không tin cậy. Các giới hạn kích thước không phải quota tổng bộ nhớ hoặc bảo vệ chống mọi DoS. Tệp kết quả có hash để truy vết nhưng chưa được ký: kiểm tra tính nhất quán trước `answer-eval` không chứng minh thứ hạng chưa bị chỉnh sửa.

Các bước tiếp theo: payload đa dạng và thích nghi; reranking; đánh giá LLM với rubric độc lập; quy trình duyệt có phân quyền, chống rollback; kiểm thử bộ nhớ và phần cứng biên. Xem [báo cáo rà soát](SECURITY_REVIEW.md).
