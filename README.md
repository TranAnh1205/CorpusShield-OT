# RAG-SEC

Dự án cá nhân nghiên cứu **an ninh AI/RAG trên dữ liệu an ninh mạng và OT**. Mã nguồn, mô hình bản ghi, bộ tải dữ liệu, bộ truy xuất, tấn công, phòng vệ và công cụ đánh giá được viết mới trong repository này. Không cần repository nghiên cứu nào khác để chạy.

Benchmark mở rộng dùng **2.743 tài liệu** từ ba nhóm: 1.745 CISA KEV, 698 MITRE ATT&CK Enterprise/ICS, và 300 CISA CSAF OT. Có 60 ca được chọn cố định (20/nhóm), mỗi ca có truy vấn gốc và truy vấn diễn đạt lại. Tất cả 60 ca bị tấn công cùng lúc với 1 hoặc 5 tài liệu độc/ca. Mỗi thiết lập chạy BM25, TF-IDF và tùy chọn MiniLM embedding, dưới sáu điều kiện nạp dữ liệu: sạch, không lọc, HMAC giả, HMAC phát lại, khóa ký bị lộ, và khóa ký bị lộ cộng snapshot đã duyệt.

## Bắt đầu

Yêu cầu Python 3.11+. CISA KEV đã có trong repository; dữ liệu ATT&CK và CSAF được tải từ **nguồn chính thức đã ghim commit và hash** vào `data/raw/`, thư mục này được bỏ qua bởi Git.

```powershell
python -m rag_sec fetch-data
python -m rag_sec full-benchmark --backend both --output results/full-benchmark.json
python -m unittest discover -s tests -v
```

Embedding là tùy chọn và cần tải model lần đầu:

```powershell
uv sync --extra embedding
uv run --extra embedding python -m rag_sec full-benchmark --backend embedding --output results/embedding-benchmark.json
```

`--backend all` chạy cả ba retriever. `--cases-per-source 2` là cách thử nhanh luồng dữ liệu trước khi chạy đủ 60 ca. Các lệnh `demo`, `evaluate`, `benchmark` giữ một lab IoT tổng hợp và benchmark KEV nhỏ chạy hoàn toàn offline.

Có thể thử **tầng câu trả lời** qua một API chat tương thích OpenAI, tự chọn model và giới hạn số truy vấn để kiểm soát chi phí. Đặt khóa trong biến môi trường `RAG_SEC_LLM_API_KEY`, rồi chạy `python -m rag_sec answer-eval --model <model> --base-url <api-v1-url> --max-queries 10`. Công cụ lưu câu trả lời để rà soát; chỉ số tự động là kiểm tra **cụm từ chính xác**, không thay thế đánh giá ngữ nghĩa thủ công. Kết quả này được bỏ qua bởi Git để tránh vô tình công bố nội dung sinh từ advisory.

## Phạm vi đo

- **Tấn công:** tài liệu giả mạo nguồn và tiêu đề, lặp truy vấn mục tiêu và đưa ra hướng dẫn sai. Truy vấn diễn đạt lại không được chèn nguyên văn vào tài liệu độc.
- **Phòng vệ:** HMAC-SHA256 xác thực toàn bộ trường bản ghi, chống chữ ký giả và phát lại. Snapshot sạch do bên tin cậy quản lý độc lập kiểm tra cả ID và nội dung khi khóa ký bị lộ.
- **Chỉ số:** tài liệu độc bất kỳ hoặc đúng ca trong top-1/top-5, tài liệu mục tiêu trong top-1/top-5, thứ hạng, ID và điểm top-5; tóm tắt theo nguồn và phiên bản truy vấn với khoảng bootstrap theo cụm ca.
- **Giới hạn:** đây là phép đo ở tầng truy xuất. Nó không chứng minh mô hình sinh câu trả lời sẽ làm theo tài liệu độc. Các ca và tài liệu độc được tạo theo mẫu cố định, không mô phỏng mọi kiểu tấn công.

## Dữ liệu và khả năng tái lập

[`data/README.md`](data/README.md) ghi nguồn, commit, hash và điều khoản. Corpus có 2.743 bản ghi từ ba nguồn công khai, nhưng **không** chứa các tệp ATT&CK/CSAF tải về trong Git. [`data/csaf-manifest.json`](data/csaf-manifest.json) lưu 300 đường dẫn và Git blob hash để dựng lại cùng bộ advisory. Kết quả JSON lưu seed, nguồn, hash, từng truy vấn và top-k. Mã mới không dùng Git history hoặc remote của một repository nghiên cứu khác.

## Cấu trúc

| Đường dẫn | Vai trò |
|---|---|
| `rag_sec/kev.py`, `rag_sec/mitre.py`, `rag_sec/csaf.py` | Xác minh và chuẩn hóa dữ liệu nguồn |
| `rag_sec/retrieval.py`, `rag_sec/tfidf.py`, `rag_sec/dense.py` | BM25, TF-IDF và dense embedding |
| `rag_sec/trust.py` | HMAC, kiểm tra phát lại, snapshot |
| `rag_sec/full_benchmark.py` | 60 ca, tấn công, điều kiện, số đo và bootstrap |
| `rag_sec/fixtures.py`, `rag_sec/experiment.py`, `rag_sec/benchmark.py` | Lab nhỏ và benchmark KEV offline |
| `tests/` | Kiểm tra dữ liệu, ranh giới tin cậy, truy xuất và kết quả |
| `results/` | Kết quả thí nghiệm có thể tái tạo |

Tài liệu chi tiết: [benchmark đa nguồn](docs/FULL_BENCHMARK.md), [kiến trúc](docs/ARCHITECTURE.md), [đánh giá KEV](docs/EVALUATION.md), [lệnh và API](docs/REFERENCE.md), [mô hình đe dọa](docs/SECURITY.md).

## Dùng trên CV

> Tự xây dựng benchmark an ninh RAG trên 2.743 bản ghi KEV, ATT&CK và CSAF OT; 60 ca, 120 truy vấn, hai mức chèn tài liệu độc và ba retriever. Triển khai cổng HMAC và snapshot độc lập, đo phơi nhiễm corpus poisoning tại top-1/top-5 dưới tấn công chữ ký giả, phát lại và khóa ký bị lộ; công bố dữ liệu nguồn đã ghim và kết quả từng truy vấn.

Chỉ dùng mô tả ba retriever khi đã chạy và lưu kết quả embedding trên môi trường của bạn. Dự án không được CISA hoặc MITRE tài trợ hay xác nhận.
