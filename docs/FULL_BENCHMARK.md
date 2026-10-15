# Benchmark đa nguồn

## Dữ liệu và ca kiểm thử

| Nhóm | Tài liệu trong corpus | Ca được chọn |
|---|---:|---:|
| CISA KEV (CVE và hành động bắt buộc) | 1.745 | 20 |
| MITRE ATT&CK Enterprise/ICS (kỹ thuật có mitigation) | 698 | 20 |
| CISA CSAF OT (advisory) | 300 | 20 |
| **Tổng** | **2.743** | **60** |

Nhóm CVE được giới hạn ở danh mục KEV của CISA, nên đây là tập lỗ hổng đã được ghi nhận khai thác thực tế. Corpus ATT&CK gồm cả Enterprise và ICS; advisory là OT từ CSAF.

Các ca được chọn theo thứ tự SHA-256 của seed cố định cộng ID mục tiêu, độc lập với thứ tự nguồn. Nhóm ATT&CK lấy 10 Enterprise và 10 ICS để đại diện cả hai môi trường. Mỗi ca có truy vấn gốc và truy vấn diễn đạt lại (120 truy vấn). Tài liệu độc chỉ dùng truy vấn gốc, tiêu đề và nhãn nguồn mục tiêu. Hai mức tải là 60 hoặc 300 tài liệu độc đồng thời. Năm biến thể văn bản độc được tạo theo mẫu cố định, có mục tiêu khuyến nghị không khắc phục.

Nguồn và hash ghi tại [data/README.md](../data/README.md). ATT&CK và CSAF phải được tải bằng `fetch-data` trước khi chạy. Không commit nội dung CSAF tải về vì có nội dung tái bản từ nhà cung cấp.

## Ma trận thử nghiệm

| Điều kiện | Bản ghi độc được chấp nhận? | Ý nghĩa |
|---|---|---|
| `clean` | Không có | Baseline |
| `unfiltered` | Có | Nạp không kiểm soát |
| `signature_forged` | Không | Chữ ký HMAC sai |
| `signature_replayed` | Không | Chữ ký thật sao chép từ bản ghi khác |
| `signature_compromised` | Có | Kẻ tấn công có khóa ký mô phỏng |
| `layered_compromised` | Không | Khóa ký lộ, nhưng ID và hash không nằm trong snapshot sạch |

Ba retriever: BM25, TF-IDF và MiniLM-L6-v2 dense embedding. Dense model được ghim revision trong `rag_sec/dense.py`, tải lần đầu từ Hugging Face. Cổng nạp dùng HMAC-SHA256 trên toàn bộ trường bản ghi. Snapshot là bản phê duyệt độc lập của corpus sạch; nếu snapshot bị thay đổi cùng khóa ký, lớp bảo vệ này cũng thất bại.

Mỗi retriever có 11 cấu hình: 1 baseline, 5 điều kiện với 1 poison/ca, 5 điều kiện với 5 poison/ca. Mỗi cấu hình có 120 truy vấn. Kết quả theo truy vấn chứa thứ hạng bản ghi đúng, poison bất kỳ và poison đúng ca; top-5 ID, điểm và số poison. Tóm tắt chứa top-1/top-5 của poison, tài liệu đúng chính xác và bản ghi liên quan theo cùng CVE hoặc kỹ thuật ATT&CK, chia theo nguồn và phiên bản truy vấn. Khoảng tin cậy 95% bootstrap lấy mẫu theo **ca**, giữ hai phiên bản truy vấn cùng nhau, với seed cố định.

## Chạy

```powershell
python -m rag_sec fetch-data
python -m rag_sec full-benchmark --backend both --output results/full-benchmark.json
uv sync --extra embedding
uv run --extra embedding python -m rag_sec full-benchmark --backend embedding --output results/embedding-benchmark.json
```

## Kết quả đã chạy

Tệp [BM25/TF-IDF](../results/full-benchmark.json) chứa 2.640 dòng theo truy vấn và 264 dòng tóm tắt; tệp [MiniLM embedding](../results/embedding-benchmark.json) chứa 1.320 dòng truy vấn và 132 dòng tóm tắt. Bảng dưới dùng 120 truy vấn và mức 1 poison/ca; `Poison@1` là số truy vấn có bất kỳ tài liệu độc nào đứng đầu, `Target@5` là số truy vấn giữ tài liệu đúng chính xác trong top-5.

| Backend | Điều kiện | Poison@1 | Target@5 | Poison bị từ chối |
|---|---|---:|---:|---:|
| BM25 | sạch | 0/120 | 120/120 | 0 |
| BM25 | không lọc | 120/120 | 114/120 | 0 |
| BM25 | chữ ký giả | 0/120 | 120/120 | 60 |
| BM25 | phát lại chữ ký | 0/120 | 120/120 | 60 |
| BM25 | khóa ký bị lộ | 120/120 | 114/120 | 0 |
| BM25 | khóa ký bị lộ + snapshot | 0/120 | 120/120 | 60 |
| TF-IDF | sạch | 0/120 | 118/120 | 0 |
| TF-IDF | không lọc | 120/120 | 104/120 | 0 |
| TF-IDF | chữ ký giả | 0/120 | 118/120 | 60 |
| TF-IDF | phát lại chữ ký | 0/120 | 118/120 | 60 |
| TF-IDF | khóa ký bị lộ | 120/120 | 104/120 | 0 |
| TF-IDF | khóa ký bị lộ + snapshot | 0/120 | 118/120 | 60 |
| Embedding | sạch | 0/120 | 88/120 | 0 |
| Embedding | không lọc | 111/120 | 68/120 | 0 |
| Embedding | chữ ký giả | 0/120 | 88/120 | 60 |
| Embedding | phát lại chữ ký | 0/120 | 88/120 | 60 |
| Embedding | khóa ký bị lộ | 111/120 | 68/120 | 0 |
| Embedding | khóa ký bị lộ + snapshot | 0/120 | 88/120 | 60 |

Với 5 poison/ca, BM25 và TF-IDF ghi `Poison@1 = 120/120`, `Target@5 = 0/120`; embedding ghi `Poison@1 = 115/120`, `Target@5 = 7/120` khi không lọc hoặc khóa ký bị lộ. Chữ ký giả, phát lại và lớp snapshot từ chối đủ 300 tài liệu độc, đưa top-5 trở về baseline sạch của từng backend. Tỷ lệ cao ở đây xuất phát từ tấn công biết truy vấn và lặp nguyên văn truy vấn trong tài liệu độc. Baseline embedding chỉ đạt 88/120 ở Target@5, nên phải so với chính baseline của nó khi diễn giải mức giảm.

Đây là đánh giá tầng truy xuất. `poison_at_5 = 1` chỉ chứng tỏ tài liệu độc sẽ nằm trong context top-5, không phải mô hình sinh đã đưa ra khuyến nghị sai. Các truy vấn và tài liệu độc được tạo theo mẫu; khoảng bootstrap không cho phép suy rộng đến mọi cuộc tấn công hay hệ thống thực tế. Backend MiniLM có giới hạn độ dài đầu vào nên phần cuối của advisory dài có thể không đi vào embedding. Bộ truy xuất không chunk hoặc rerank tài liệu.
