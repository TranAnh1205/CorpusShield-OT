# Mô hình đe dọa và giới hạn

## Quyền của kẻ tấn công

Kẻ tấn công có thể thêm tài liệu vào nguồn nạp và biết truy vấn đánh giá. Ở điều kiện mạnh hơn, họ có khóa HMAC và ký được tài liệu độc. Benchmark không cho họ sửa corpus KEV gốc, snapshot đã duyệt, mã chạy hoặc kết quả sau khi truy xuất.

HMAC có tác dụng khi khóa chưa lộ: chữ ký giả bị từ chối. Nếu khóa lộ, HMAC không phân biệt tài liệu sạch và tài liệu độc đã được ký. Snapshot chỉ có tác dụng nếu được tạo từ dữ liệu sạch đã rà soát **trước** khi nhận tài liệu của kẻ tấn công, được lưu trong miền quyền riêng, và mọi thay đổi hợp lệ phải qua phê duyệt. Nếu snapshot bị sửa hoặc được tạo từ corpus đã nhiễm độc, hàng rào này không còn ý nghĩa.

## Phạm vi bảo đảm

Thí nghiệm chỉ kiểm tra cổng nạp và mức phơi nhiễm top-k. Nó không xác thực nội dung của advisory, không bảo đảm KEV chính xác, không phát hiện prompt injection trong tài liệu đã duyệt và không bảo đảm câu trả lời LLM an toàn. HMAC là mô phỏng trong cùng tiến trình với khóa cố định ở benchmark để tái lập, không phải quản lý khóa dùng trong sản xuất. Dự án chưa triển khai luồng duyệt snapshot, phân quyền, lưu trữ khóa, nhật ký kiểm toán hay dịch vụ RAG hoàn chỉnh.

Các bước mở rộng hữu ích: bộ tấn công không biết truy vấn và nhiều kiểu payload; dense retrieval/reranking; đánh giá câu trả lời LLM với rubric độc lập; snapshot có quy trình phê duyệt và kho riêng; kiểm thử hiệu năng với corpus lớn hơn. Mọi mở rộng cần ghi rõ dữ liệu, quyền sử dụng, nhãn đánh giá và giới hạn suy luận.
