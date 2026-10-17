# Rà soát CorpusShield-OT — 16/10/2026

## Phạm vi và kết luận

Rà mã ứng dụng `rag_sec`, loader dữ liệu, HMAC/snapshot, truy xuất, đánh giá câu trả lời, CLI, kiểm thử, khóa phụ thuộc và CI. Bản gốc của đợt rà là commit `18c64a3`; thay đổi nằm trên nhánh `codex/corpusshield-security-audit`. Đây là công cụ benchmark chạy từ source checkout, chưa phải dịch vụ bảo mật vận hành thực tế. Không sửa repo Kh3m hoặc các bản RAG-SEC khác.

Đã sửa các điểm yếu xác nhận được bên dưới và thêm bằng chứng thực nghiệm. Kết quả quét không chứng minh không còn lỗ hổng. Không thực hiện pentest hệ điều hành, dịch vụ triển khai hoặc API LLM trực tiếp.

## Các điểm đã sửa

| Điểm yếu trước sửa | Điều kiện / tác động | Thay đổi |
|---|---|---|
| HTTP endpoint và redirect mặc định của API LLM | Endpoint không an toàn hoặc chuyển hướng có thể làm lộ Authorization | Bắt buộc HTTPS trừ loopback được chọn rõ; chặn redirect; kiểm thử bằng HTTP server cục bộ |
| Đọc phản hồi và dữ liệu không giới hạn | Nguồn lỗi có thể tiêu tốn bộ nhớ | Giới hạn byte cho nguồn, snapshot, kết quả và phản hồi; kiểm tra kiểu câu trả lời |
| Manifest CSAF chưa có hash tin cậy độc lập trong mã | Sửa manifest có thể thay cả danh sách và hash được tin cậy | Ghim SHA-256 manifest sau chuẩn hóa LF để dùng cùng hash trên Windows/Linux; kiểm tra commit, đường dẫn, trùng lặp và giới hạn workers |
| KEV xác minh rồi đọc lại để phân tích | Tệp bị đổi giữa hai lần đọc có thể qua bước xác minh trước đó | Xác minh và phân tích cùng vùng byte |
| Tệp tải/kết quả có thể bị ghi dở | Lỗi giữa chừng hoặc đụng tệp tạm làm hỏng artifact | Tệp tạm riêng, fsync, thay thế nguyên tử; chỉ xuất bản nguồn sau xác minh |
| Snapshot còn tham chiếu dữ liệu của bên gọi | Iterator có thể thay approval trong khi ingest | Kiểm tra schema, sao chép pins trước vòng lặp; kiểm thử tình huống thay đổi |
| Snapshot benchmark chỉ tạo trong tiến trình | Chưa thử được luồng approval được lưu trước đó | Thêm xuất/đọc snapshot với SHA-256 từ cấu hình tin cậy; ghi rõ provided/simulated |
| `answer-eval` tin metadata và ID trong kết quả đầu vào | Context sai nguồn/ca có thể bị gửi đi và kết quả bị diễn giải sai | Kiểm tra revision, hash, câu hỏi, ID, điểm, trùng lặp trước mọi lời gọi model |
| Lấy mẫu câu trả lời theo các hàng đầu | Thiên lệch nguồn khi ngân sách nhỏ | Round-robin theo nguồn và phiên bản truy vấn, thứ tự ca cố định bằng hash |
| Cụm từ chính xác bị coi như dấu hiệu tấn công thành công | Câu phủ định/trích dẫn vẫn chứa cụm từ | Ghi rõ lexical presence; `manual_verdict` để trống chờ đánh giá người thật |
| Tham số truy xuất và kích thước record chưa chặt | NaN, kiểu sai, chuỗi quá lớn gây kết quả/lỗi khó đoán | Kiểm tra tham số BM25, top-k, truy vấn, record và chữ ký |
| Kết quả thiếu dấu vết phiên bản chạy | Khó tái lập và quy kết số liệu cho mã | Schema 2 ghi code hashes, Git dirty state, môi trường, corpus/case hash và thời gian |

CLI từ chối ghi đè kết quả nếu thiếu `--overwrite`; snapshot luôn yêu cầu đường dẫn mới. Đây là bảo vệ thao tác thông thường, không phải cơ chế khóa nhiều tiến trình hay bảo vệ khỏi người có quyền ghi thư mục. BM25 sắp xếp token trước cộng điểm để giảm phụ thuộc Python hash seed.

## Kiểm chứng đã thực hiện

- `python -m unittest discover -s tests -v`: **34/34 đạt**, lần cuối 77,357 giây. Baseline có 18 test. Kiểm thử mới bao gồm redirect, giới hạn dung lượng, manifest bị sửa, snapshot bị thay trong ingest, cập nhật hợp lệ phải duyệt lại, ghi tệp thất bại và đầu vào answer-eval sai bị chặn trước khi gọi model.
- Bandit **1.9.4**: trước sửa 6 cảnh báo; sau rà soát 0 cảnh báo còn lại trong cấu hình. Sáu cảnh báo ban đầu không tương đương sáu lỗ hổng: random dùng bootstrap là thống kê; SHA-1 dùng nhận dạng Git blob theo manifest; các ngoại lệ `nosec` có giải thích tại mã. Chúng không phải chứng minh mật mã hay miễn trừ toàn file.
- Ruff **0.17.1**, `--isolated --select E4,E7,E9,F`: đạt. Không tuyên bố mọi quy tắc lint đều được bật.
- pip-audit **2.10.1** trên export của lock với toàn bộ extras: **42 gói được chọn trên Windows, 0 lỗ hổng đã biết được báo**, không có gói bị bỏ qua trong kết quả audit. Phụ thuộc chỉ dành cho nền tảng khác chưa được kiểm chứng bằng lần chạy này.
- Quét mẫu khóa phổ biến trong mã được Git theo dõi: không thấy khớp. Đây không phải quét toàn bộ lịch sử Git hoặc mọi dạng bí mật.
- `git diff --check`: đạt. CI đã thêm audit, pin GitHub Actions bằng SHA và thử snapshot được lưu; chưa có kết quả chạy GitHub CI cho nhánh này.

## Benchmark mới có số liệu thực

[Kết quả query-blind](../results/security-review-query-blind.json): 2.743 bản ghi, 60 ca, hai phiên bản truy vấn/ca, hai retriever, 11 cấu hình/retriever; **2.640 hàng truy vấn và 264 tóm tắt**. Snapshot đọc từ tệp đã xuất trước lượt chạy và kiểm tra SHA-256. Payload dùng tiêu đề mục tiêu công khai, không sao chép cả truy vấn gốc lẫn truy vấn diễn đạt lại.

| Retriever | Poison/ca | Poison@1 không lọc | Target@5 không lọc | Poison@1 khi khóa lộ + snapshot | Target@5 khi khóa lộ + snapshot |
|---|---:|---:|---:|---:|---:|
| BM25 | 1 | 117/120 | 120/120 | 0/120 | 120/120 |
| BM25 | 5 | 117/120 | 2/120 | 0/120 | 120/120 |
| TF-IDF | 1 | 120/120 | 118/120 | 0/120 | 118/120 |
| TF-IDF | 5 | 120/120 | 0/120 | 0/120 | 118/120 |

Khóa ký bị lộ mà không có snapshot cho kết quả giống không lọc. Snapshot từ chối 60 hoặc 300 bản ghi độc tương ứng; baseline sạch là BM25 120/120 và TF-IDF 118/120 Target@5. Không suy ra khả năng chống mọi tấn công từ con số 0/120. Snapshot là allowlist baseline nên việc chặn ID/nội dung mới là thuộc tính thiết kế, không chứng minh phát hiện ngữ nghĩa độc hại.

Đã tính lại các count từ toàn bộ hàng truy vấn và đối chiếu tất cả 264 tóm tắt: không lệch. Code hash trong artifact được đối chiếu với mã sau lần chạy. Artifact ghi working tree dirty đúng thực tế; hashes giúp nhận diện chính xác mã chưa commit. Thời gian chạy có cạnh tranh tài nguyên với kiểm thử trên cùng máy, không dùng làm so sánh tốc độ hay SLA. Chưa chạy lại dense với tấn công mới; số liệu MiniLM cũ vẫn thuộc benchmark query-aware cũ.

## Những việc còn cần cải thiện

1. **Ưu tiên cao trước triển khai:** quản lý khóa ngoài tiến trình, phân quyền nguồn/approval, nhật ký duyệt, chữ ký approval, chống rollback và quy trình thu hồi. Người sửa được cả mã lẫn hash tin cậy vẫn vượt được mô hình hiện tại.
2. **Ưu tiên cao cho bằng chứng AI:** bộ câu hỏi và nhãn độc lập, payload đa dạng/thích nghi, đánh giá LLM bằng rubric người thật. Hiện chưa có tỷ lệ gây hại ở câu trả lời hay đánh giá mô hình sinh trực tiếp.
3. **Chất lượng truy xuất:** chunking, hybrid retrieval, reranker và ablation trên holdout; kiểm tra ảnh hưởng cắt ngắn advisory của MiniLM. Chưa thể nói hệ thống vượt repo khác chỉ bằng số module hoặc test.
4. **Tính toàn vẹn kết quả:** ký artifact hoặc tái tính ranking khi nhập; hiện kiểm tra hash/metadata không xác thực tính trung thực của thứ hạng đã lưu. Chưa có approval cho từng tài liệu theo vòng đời vận hành.
5. **Khả năng vận hành:** quota tổng, giới hạn thời gian toàn job, đo bộ nhớ, dữ liệu lớn, nhiều tiến trình, phần cứng OT và wheel chứa tài nguyên. Giới hạn từng input chưa xử lý mọi hình thức DoS.
6. **Chuỗi cung ứng:** audit thêm môi trường Linux/CI, kiểm tra cập nhật định kỳ, xác định chính sách nguồn và giấy phép mã. SHA-1 của blob không thay thế chữ ký upstream; một nguồn đã bị xâm nhập trước khi duyệt vẫn có thể được ghim.

API endpoint do người vận hành tin cậy cấu hình. Không dùng helper mạng này như một bộ lọc SSRF cho URL tùy ý từ Internet. Chưa có web/API server để kiểm thử auth, phân quyền người dùng hay rate limiting.
