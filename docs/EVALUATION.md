# Thiết kế đánh giá

## Corpus, ca và tấn công

Corpus là 1.745 bản ghi từ [bản CISA KEV đã ghim](../data/README.md). Trong số đó, 40 CVE được chọn bằng SHA-256 của chuỗi `rag-sec-kev-v1:<CVE ID>`, lấy 40 giá trị nhỏ nhất; thứ tự gốc của tệp không ảnh hưởng lựa chọn. Mỗi CVE có một truy vấn chứa CVE/vendor/product và một truy vấn theo tên lỗ hổng/product, tổng cộng 80 truy vấn. Nhãn mục tiêu là CVE ID từ chính KEV. Không có nhãn thủ công về tính đúng đắn của `requiredAction`.

Kẻ tấn công biết trước hai truy vấn của từng CVE và chèn một bản ghi mang lại các cụm từ đó cùng câu lệnh cố gắng khiến trợ lý bỏ qua khuyến nghị tin cậy. Cả 40 bản ghi độc được đưa vào cùng lúc. Đây là tấn công có chủ đích và có lợi thế truy vấn, không phải mẫu ngẫu nhiên của tấn công thực tế.

## Năm điều kiện

| Điều kiện | Corpus vào retriever |
|---|---|
| `clean` | Chỉ KEV sạch. |
| `unfiltered` | KEV cộng 40 tài liệu độc, bỏ qua cổng nạp. |
| `signature_forged` | HMAC kiểm tra chữ ký giả của tài liệu độc. |
| `signature_compromised` | Tài liệu độc được ký bằng khóa mô phỏng bị lộ; chỉ dùng HMAC. |
| `layered_compromised` | Cùng tình huống khóa lộ, thêm snapshot sạch được bảo vệ riêng. |

Mỗi điều kiện chạy BM25 và TF-IDF, lấy top-5. `poison_at_k` đếm truy vấn có ít nhất một ID `injected-` trong top-k; `target_at_k` đếm truy vấn có bản ghi KEV mục tiêu trong top-k. `rejected_records` đếm envelope bị chặn khi nạp, không phải số truy vấn. `bootstrap_95` trong JSON là khoảng percentile từ 2.000 lần lấy mẫu lại theo **cụm CVE**, giữ hai truy vấn cùng nhau; khoảng này chỉ mô tả độ biến thiên trong tập CVE được chọn và không chứng minh hiệu quả ở môi trường khác.

## Kết quả

| Retriever | Điều kiện | Poison@1 | Poison@5 | Target@1 | Target@5 | Rejected |
|---|---|---:|---:|---:|---:|---:|
| BM25 | clean | 0/80 | 0/80 | 64/80 | 76/80 | 0 |
| BM25 | unfiltered | 80/80 | 80/80 | 0/80 | 72/80 | 0 |
| BM25 | signature_forged | 0/80 | 0/80 | 64/80 | 76/80 | 40 |
| BM25 | signature_compromised | 80/80 | 80/80 | 0/80 | 72/80 | 0 |
| BM25 | layered_compromised | 0/80 | 0/80 | 64/80 | 76/80 | 40 |
| TF-IDF | clean | 0/80 | 0/80 | 64/80 | 75/80 | 0 |
| TF-IDF | unfiltered | 74/80 | 80/80 | 6/80 | 75/80 | 0 |
| TF-IDF | signature_forged | 0/80 | 0/80 | 64/80 | 75/80 | 40 |
| TF-IDF | signature_compromised | 74/80 | 80/80 | 6/80 | 75/80 | 0 |
| TF-IDF | layered_compromised | 0/80 | 0/80 | 64/80 | 75/80 | 40 |

Tệp [`results/kev-benchmark.json`](../results/kev-benchmark.json) chứa kết quả từng truy vấn, top-5 ID và các khoảng bootstrap. Có thể tái tạo bằng:

```powershell
python -m rag_sec benchmark --output results/kev-benchmark.json
python -m unittest discover -s tests -v
```

## Diễn giải và giới hạn

Baseline sạch đã bỏ lỡ mục tiêu ở 4/80 truy vấn với BM25 và 5/80 với TF-IDF tại top-5. Việc chặn tài liệu độc trở về đúng baseline đó, không làm bộ truy xuất hoàn hảo. Tài liệu độc được tối ưu trực tiếp cho truy vấn nên Poison@1 cao là đặc điểm của kịch bản này. Hai truy vấn trên mỗi CVE có liên quan; không được diễn giải 80 phép đo là 80 CVE độc lập.

Benchmark không gọi LLM và không đo tỷ lệ câu trả lời độc hại, mức độ nghe theo prompt injection, chất lượng khuyến nghị hay tác động vận hành. Corpus chỉ gồm văn bản ngắn KEV, không có chunking, embedding, reranking, tài liệu web dài hay thay đổi dữ liệu theo thời gian. Tám fixture IoT nhỏ của lệnh `evaluate` chỉ là kiểm tra chức năng tách biệt với benchmark KEV.
