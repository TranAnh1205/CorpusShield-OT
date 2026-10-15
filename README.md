# RAG-SEC

RAG-SEC là dự án cá nhân về **an ninh AI/RAG và đánh giá tấn công corpus poisoning**. Dự án đo việc tài liệu do kẻ tấn công chèn vào corpus có xuất hiện trong top-k truy xuất, rồi kiểm tra hai ranh giới nạp dữ liệu: HMAC-SHA256 và snapshot nội dung đã duyệt độc lập.

Benchmark chính dùng **1.745 bản ghi CISA Known Exploited Vulnerabilities (KEV)**, 40 CVE được chọn cố định, hai truy vấn cho mỗi CVE, hai retriever (BM25, TF-IDF) và năm điều kiện tấn công/phòng vệ. Mọi thí nghiệm chạy offline sau khi clone repo. [Nguồn dữ liệu và giấy phép](data/README.md).

## Chạy nhanh

Yêu cầu Python 3.11+. Không cần cài package ngoài để chạy mã:

```powershell
python -m rag_sec benchmark --output results/kev-benchmark.json
python -m unittest discover -s tests -v
```

Lệnh `python -m rag_sec demo` và `python -m rag_sec evaluate` chạy lab nhỏ với tám tình huống IoT giả định. Có thể cài entry point bằng `python -m pip install -e .`.

## Kết quả benchmark đã chạy

Mỗi dòng là 80 truy vấn trên cùng 40 CVE. `Poison@1` là số truy vấn có tài liệu độc đứng đầu; `Target@5` là số truy vấn còn thấy bản ghi KEV mục tiêu trong năm kết quả đầu. Tệp [kết quả đầy đủ](results/kev-benchmark.json) gồm top-5 từng truy vấn và khoảng bootstrap theo cụm CVE.

| Retriever | Điều kiện | Poison@1 | Target@5 | Bản ghi bị từ chối |
|---|---|---:|---:|---:|
| BM25 | Corpus sạch | 0/80 | 76/80 | 0 |
| BM25 | Không lọc | 80/80 | 72/80 | 0 |
| BM25 | HMAC, chữ ký giả | 0/80 | 76/80 | 40 |
| BM25 | HMAC, khóa ký bị lộ | 80/80 | 72/80 | 0 |
| BM25 | HMAC + snapshot, khóa ký bị lộ | 0/80 | 76/80 | 40 |
| TF-IDF | Corpus sạch | 0/80 | 75/80 | 0 |
| TF-IDF | Không lọc | 74/80 | 75/80 | 0 |
| TF-IDF | HMAC, chữ ký giả | 0/80 | 75/80 | 40 |
| TF-IDF | HMAC, khóa ký bị lộ | 74/80 | 75/80 | 0 |
| TF-IDF | HMAC + snapshot, khóa ký bị lộ | 0/80 | 75/80 | 40 |

Tài liệu độc được xây từ chính hai truy vấn của CVE mục tiêu, nên đây là **tấn công biết truy vấn**. Kết quả đo **mức phơi nhiễm ở tầng truy xuất**, không đo LLM làm theo chỉ dẫn độc hay đưa ra khuyến nghị sai. Snapshot chỉ chặn được tài liệu chưa duyệt khi bản snapshot sạch và được bảo vệ khỏi kẻ tấn công. Xem [thiết kế đánh giá](docs/EVALUATION.md) và [mô hình đe dọa](docs/SECURITY.md).

## Luồng thí nghiệm

```text
CISA KEV JSON đã ghim SHA-256 → bản ghi chuẩn hóa → corpus sạch
                                               ↘ tài liệu độc theo truy vấn
envelope → kiểm tra HMAC → đối chiếu snapshot đã duyệt → BM25 / TF-IDF → top-5 → chỉ số
```

## Cấu trúc và tài liệu

| Đường dẫn | Nội dung |
|---|---|
| `data/` | Bản KEV ghim theo commit, SHA-256, giấy phép CC0. |
| `rag_sec/kev.py` | Kiểm tra hash và chuyển KEV sang định dạng bản ghi. |
| `rag_sec/retrieval.py`, `rag_sec/tfidf.py` | Hai baseline truy xuất từ vựng. |
| `rag_sec/records.py`, `rag_sec/trust.py` | Chuẩn hóa, HMAC và snapshot. |
| `rag_sec/benchmark.py` | Chọn ca, tạo tấn công, chạy năm điều kiện và tính chỉ số. |
| `rag_sec/fixtures.py`, `rag_sec/experiment.py` | Lab IoT tổng hợp nhỏ, chạy độc lập. |
| `tests/` | Kiểm tra dữ liệu, độ lặp lại, truy xuất và ranh giới tin cậy. |
| `results/kev-benchmark.json` | Kết quả đã chạy với ID top-5 của từng truy vấn. |

- [Kiến trúc](docs/ARCHITECTURE.md)
- [Thiết kế đánh giá](docs/EVALUATION.md)
- [Lệnh và API](docs/REFERENCE.md)
- [Mô hình đe dọa và giới hạn](docs/SECURITY.md)

## Cách mô tả trên CV

> Xây benchmark corpus poisoning cho RAG trên 1.745 bản ghi CISA KEV (CC0): 40 CVE, 80 truy vấn, BM25/TF-IDF và năm điều kiện tấn công/phòng vệ; triển khai HMAC và snapshot độc lập, công bố chỉ số top-k cùng kết quả từng truy vấn có thể tái lập.

Mã benchmark và fixture IoT được viết riêng cho dự án này. Dữ liệu KEV thuộc CISA, phân phối theo CC0. Chưa chọn giấy phép phát hành cho **mã của dự án**; cần chọn trước khi công bố để người khác tái sử dụng mã.
