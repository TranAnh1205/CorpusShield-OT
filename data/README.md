# Nguồn dữ liệu CISA KEV

- Nguồn: [cisagov/kev-data](https://github.com/cisagov/kev-data)
- Bản ghi: [`known_exploited_vulnerabilities.json` tại commit đã ghim](https://github.com/cisagov/kev-data/blob/7606917390b43dc02b251d88dbceed6296a919fc/known_exploited_vulnerabilities.json)
- Commit: `7606917390b43dc02b251d88dbceed6296a919fc`
- SHA-256 tệp JSON: `47b463a136b8e0956756cfbcdbc2e4b4ccb60c96b4ca7a1ca9f507817cc83045`
- Ngày lấy dữ liệu: 2026-10-15
- Số bản ghi theo tệp: 1.745
- Giấy phép dữ liệu: [CC0 1.0 của CISA](https://github.com/cisagov/kev-data/blob/7606917390b43dc02b251d88dbceed6296a919fc/LICENSE); bản sao ở `CISA-KEV-LICENSE`.

Tệp JSON được giữ nguyên byte để SHA-256 kiểm tra chính xác. `rag_sec/kev.py` từ chối tệp bị thay đổi hoặc số lượng/ID bản ghi không hợp lệ. Mã benchmark chỉ dùng các trường CVE ID, vendor, product, vulnerability name, short description và required action. Các liên kết tới bên thứ ba trong dữ liệu có điều khoản riêng; dự án không sao chép nội dung từ các trang đó. CISA/DHS không tài trợ hay xác nhận dự án.

## MITRE ATT&CK

- Nguồn: [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data), Enterprise và ICS phiên bản 20.0.
- Commit ghim: `c2494b29dd268c46a5d0ea0990553e4327cd2253`.
- SHA-256 Enterprise: `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`.
- SHA-256 ICS: `c9ca0ce523a1b5e512060a390415e8aefe8f6d32c5f82d7de81264960c1e1183`.
- Giấy phép gốc: [MITRE ATT&CK license tại commit đã ghim](https://github.com/mitre-attack/attack-stix-data/blob/c2494b29dd268c46a5d0ea0990553e4327cd2253/LICENSE.txt); bản sao ở `MITRE-ATTACK-LICENSE.txt`.

Lệnh `python -m rag_sec fetch-data` tải hai tệp STIX vào `data/raw/` và kiểm tra SHA-256. Tệp gốc không được commit; `rag_sec/mitre.py` tạo 698 bản ghi kỹ thuật đang hoạt động có mitigation. Cần giữ ghi công MITRE khi công bố kết quả hoặc nội dung phát sinh.

## CISA CSAF OT

- Nguồn: [cisagov/CSAF](https://github.com/cisagov/CSAF), nhánh dữ liệu `csaf_files/OT/white`.
- Commit ghim: `773131a0fb11aa4ee71d03980725932ababa47e9`.
- `csaf-manifest.json` liệt kê 300 advisory chọn bằng SHA-256 của seed `rag-sec-csaf-ot-2026-v1` và đường dẫn trong 1.734 tệp ứng viên 2023–2026; mỗi entry có Git blob SHA-1 để xác nhận byte tải về.

Lệnh `python -m rag_sec fetch-data` tải các advisory vào `data/raw/`; không commit nội dung gốc hoặc corpus tạo từ advisory vì một số tệp tái bản nội dung của nhà cung cấp có điều khoản riêng. Mã và manifest có thể công bố độc lập. Khi công bố trích đoạn advisory, kiểm tra điều khoản tại nguồn tương ứng.

## Mô hình embedding tùy chọn

`sentence-transformers/all-MiniLM-L6-v2` tại revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41` được tải qua thư viện Sentence Transformers khi chọn backend `embedding`. [Model card và giấy phép Apache-2.0](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) thuộc bên phát hành mô hình. Trọng số không nằm trong repository này.
