# Lệnh và API

## Lệnh

Chạy từ thư mục gốc với Python 3.11+:

```powershell
python -m rag_sec fetch-data
python -m rag_sec full-benchmark --backend both --output results/latest-benchmark.json
uv run --extra embedding python -m rag_sec full-benchmark --backend embedding --output results/embedding-latest.json
python -m rag_sec benchmark --backend both --output results/kev-latest.json
python -m rag_sec benchmark --backend bm25
python -m rag_sec benchmark --backend tfidf
python -m rag_sec demo --case 4
python -m rag_sec evaluate --output results/fixture-latest.json
python -m rag_sec snapshot --output results/approved-fixture.json
python -m unittest discover -s tests -v
```

`benchmark` dùng bản CISA KEV nằm trong `data/`; mặc định chạy cả BM25 và TF-IDF. Kết quả JSON có `summary` và `per_query`. `demo`, `evaluate` dùng tám fixture IoT tự viết; `snapshot` mặc định dùng fixture nhưng hỗ trợ `--source corpus` để xuất snapshot toàn bộ dữ liệu đã xác minh.

`fetch-data` là lệnh duy nhất cần tải ATT&CK và CSAF; các tệp gốc được lưu ngoài Git. `full-benchmark` dùng dữ liệu đã tải, có `--cases-per-source` và ba backend `bm25`, `tfidf`, `embedding` (`both` hoặc `all`). Tệp kết quả đa nguồn có thể lưu vào Git vì chỉ ghi ID, điểm truy xuất và metadata, không ghi nội dung advisory. Xem [benchmark đa nguồn](FULL_BENCHMARK.md).

`answer-eval` nhận `--input`, `--backend`, `--condition`, `--poisons-per-case`, `--max-queries`, `--model` và `--base-url`. Nó kiểm tra nguồn, ca đánh giá và ID của toàn bộ hàng được chọn trước khi gửi top-5 văn bản tới endpoint bằng khóa trong `RAG_SEC_LLM_API_KEY`. Mẫu được phân bổ theo nguồn và phiên bản truy vấn. Cụm từ khớp có thể nằm trong câu phủ định; không dùng nó làm tỷ lệ tấn công thành công. Endpoint bắt buộc HTTPS, ngoại trừ HTTP loopback được chỉ định; redirect bị chặn. Tệp đầu ra mặc định `results/answer-eval.json` được bỏ qua bởi Git.

`full-benchmark --attack-mode query-blind` tạo payload từ tiêu đề mục tiêu công khai, không dùng truy vấn gốc hay diễn đạt lại. Mặc định vẫn là `query-aware`. `--approved-snapshot PATH` phải đi cùng `--snapshot-sha256 HASH` lấy từ cấu hình tin cậy riêng. Snapshot phải khớp baseline hiện tại; thay đổi hợp lệ cần duyệt lại. Khi không truyền, snapshot là mô phỏng trong tiến trình.

Các lệnh ghi kết quả từ chối đường dẫn đã tồn tại trừ khi có `--overwrite`. Lệnh `snapshot` không cho ghi đè. Ghi tệp dùng thay thế nguyên tử; đây không phải cơ chế khóa giữa nhiều tiến trình. Schema 2 bổ sung trường `run`, `snapshot`, `attack_mode`, và thông tin thời gian chạy. Chạy từ source checkout; wheel chưa đóng gói dữ liệu.

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
