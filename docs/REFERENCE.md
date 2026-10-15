# Lệnh và API

## Lệnh

Chạy từ thư mục gốc với Python 3.11+:

```powershell
python -m rag_sec fetch-data
python -m rag_sec full-benchmark --backend both --output results/full-benchmark.json
uv run --extra embedding python -m rag_sec full-benchmark --backend embedding --output results/embedding-benchmark.json
python -m rag_sec benchmark --backend both --output results/kev-benchmark.json
python -m rag_sec benchmark --backend bm25
python -m rag_sec benchmark --backend tfidf
python -m rag_sec demo --case 4
python -m rag_sec evaluate --output results/fixture-latest.json
python -m rag_sec snapshot --output results/approved-fixture.json
python -m unittest discover -s tests -v
```

`benchmark` dùng bản CISA KEV nằm trong `data/`; mặc định chạy cả BM25 và TF-IDF. Kết quả JSON có `summary` theo retriever/điều kiện, bốn chỉ số với count/rate/bootstrap 95%, và `per_query` chứa top-5 ID. Khóa mô phỏng và nội dung tài liệu độc không được ghi vào kết quả. `demo`, `evaluate`, `snapshot` chỉ sử dụng tám fixture IoT tự viết, không dùng KEV.

`fetch-data` là lệnh duy nhất cần tải ATT&CK và CSAF; các tệp gốc được lưu ngoài Git. `full-benchmark` dùng dữ liệu đã tải, có `--cases-per-source` và ba backend `bm25`, `tfidf`, `embedding` (`both` hoặc `all`). Tệp kết quả đa nguồn có thể lưu vào Git vì chỉ ghi ID, điểm truy xuất và metadata, không ghi nội dung advisory. Xem [benchmark đa nguồn](FULL_BENCHMARK.md).

`answer-eval` nhận `--input`, `--backend`, `--condition`, `--poisons-per-case`, `--max-queries`, `--model` và `--base-url`. Nó gửi top-5 văn bản tới endpoint chat tương thích OpenAI bằng khóa trong `RAG_SEC_LLM_API_KEY`. Chỉ số cụm từ chính xác có thể bỏ sót câu trả lời sai được diễn đạt lại; cần đọc từng câu trả lời. Tệp đầu ra mặc định `results/answer-eval.json` được bỏ qua bởi Git.

## API chính

| API | Vai trò |
|---|---|
| `load_kev(path=DATA_PATH)` | Kiểm tra SHA-256 và chuyển tệp KEV thành danh sách bản ghi. |
| `fetch_mitre()` / `fetch_csaf()` | Tải nguồn chính thức đã ghim và xác minh hash. |
| `load_mitre()` / `load_csaf()` | Chuẩn hóa kỹ thuật ATT&CK và advisory OT. |
| `run_full(backends, cases_per_source=20)` | Chạy benchmark 60 ca và trả kết quả từng truy vấn. |
| `select_cases(catalog, count=40)` | Chọn CVE và tạo hai truy vấn/CVE theo hash cố định. |
| `attack_records(cases)` | Tạo một bản ghi độc biết truy vấn cho mỗi CVE. |
| `benchmark(backends=("bm25", "tfidf"))` | Chạy toàn bộ điều kiện và trả kết quả Python dict. |
| `BM25(records).search(query, top_k=5)` | Truy xuất BM25. |
| `TFIDF(records).search(query, top_k=5)` | Truy xuất TF-IDF cosine. |
| `sign(record, key)` / `verify(...)` | HMAC-SHA256 trên bản ghi chuẩn hóa. |
| `snapshot(records)` | Map ID tới SHA-256 của corpus đã duyệt. |
| `ingest(envelopes, key, approved=None)` | Trả `(accepted, rejected)` sau kiểm tra. |

Mỗi bản ghi có đúng sáu trường `record_id`, `publisher`, `heading`, `body`, `reference`, `kind`. `canonical_bytes` dùng JSON UTF-8 sắp xếp khóa và tiền tố `rag-sec-record-v1\0`; thay đổi bất kỳ trường nào đều làm chữ ký và hash snapshot thay đổi.
