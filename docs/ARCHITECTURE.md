# Kiến trúc

## Benchmark đa nguồn

`csaf.py`, `mitre.py` và `kev.py` đọc ba bộ dữ liệu đã ghim rồi chuyển thành cùng bản ghi sáu trường. `full_benchmark.py` chọn 20 ca mỗi nhóm, tạo hai truy vấn/ca và 1 hoặc 5 tài liệu độc/ca. Cùng corpus đi qua cổng nạp HMAC, snapshot tùy điều kiện, rồi BM25, TF-IDF hoặc dense embedding. Chi tiết ma trận và số đo ở [benchmark đa nguồn](FULL_BENCHMARK.md).

```text
KEV / ATT&CK / CSAF → kiểm tra hash → 2.743 bản ghi sạch
                                    ↓
                        60 ca × 2 truy vấn
                                    ↓
                      60 hoặc 300 poison → HMAC → snapshot → retriever → top-k
```

Các phần dưới mô tả benchmark KEV nhỏ được giữ để chạy hoàn toàn offline sau khi clone.

## Thành phần và luồng dữ liệu

`kev.py` đọc dữ liệu KEV đã ghim, kiểm tra SHA-256 và chuyển từng CVE thành bản ghi sáu trường. `benchmark.py` chọn 40 CVE bằng thứ tự hash ổn định, tạo hai truy vấn cho mỗi CVE và một tài liệu độc cho mỗi CVE. Mọi tài liệu độc được đưa vào cùng một corpus ở điều kiện có tấn công.

```text
KEV JSON → kiểm tra SHA-256 → 1.745 bản ghi sạch ─────────────┐
                                  40 CVE → 80 truy vấn         ├→ ingest → BM25/TF-IDF → top-5
                                  40 tài liệu độc ── HMAC ─────┘      ↑
                                             snapshot đã duyệt ───────┘
```

`records.py` yêu cầu đúng sáu trường chuỗi không rỗng: `record_id`, `publisher`, `heading`, `body`, `reference`, `kind`. Dữ liệu KEV tạo `record_id=CVE ID`, tiêu đề gồm ID/vendor/product/tên lỗ hổng, nội dung gồm mô tả ngắn và `requiredAction`. Hai retriever chỉ lập chỉ mục `heading + body`.

## Ranh giới tin cậy

Một envelope có dạng `{"record": {...}, "signature": "..."}`. `trust.py` chuẩn hóa JSON UTF-8 với tiền tố phiên bản trước khi ký HMAC-SHA256. Snapshot lưu `record_id → SHA-256(canonical record)` của corpus sạch đã duyệt. `ingest` chỉ đưa bản ghi qua cả hai kiểm tra vào retriever khi điều kiện có snapshot.

HMAC xác nhận bên ký có khóa; nó không chứng minh nội dung đúng. Snapshot xác nhận bản ghi là đúng byte đã duyệt; nó không tự phê duyệt nội dung. Nếu khóa ký bị lộ, chữ ký của tài liệu độc hợp lệ và chỉ snapshot độc lập còn từ chối được nó. Benchmark dùng khóa cố định chỉ cho mô phỏng, không phải phương án quản lý khóa sản xuất.

## Truy xuất

`BM25` dùng `k1=1.2`, `b=0.75`, IDF không âm. `TFIDF` dùng tần số log, IDF làm trơn và cosine. Cả hai dùng tokenizer ASCII chữ/số, biến query thành các token thường và giữ thứ tự corpus khi đồng điểm. `dense.py` dùng MiniLM-L6-v2 ở revision ghim, vector chuẩn hóa và cosine; embedding được cache theo hash nội dung để các điều kiện không encode lặp. Dự án chưa có reranker hay bước sinh câu trả lời.
