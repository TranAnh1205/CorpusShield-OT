# Nguồn dữ liệu CISA KEV

- Nguồn: [cisagov/kev-data](https://github.com/cisagov/kev-data)
- Bản ghi: [`known_exploited_vulnerabilities.json` tại commit đã ghim](https://github.com/cisagov/kev-data/blob/7606917390b43dc02b251d88dbceed6296a919fc/known_exploited_vulnerabilities.json)
- Commit: `7606917390b43dc02b251d88dbceed6296a919fc`
- SHA-256 tệp JSON: `47b463a136b8e0956756cfbcdbc2e4b4ccb60c96b4ca7a1ca9f507817cc83045`
- Ngày lấy dữ liệu: 2026-10-15
- Số bản ghi theo tệp: 1.745
- Giấy phép dữ liệu: [CC0 1.0 của CISA](https://github.com/cisagov/kev-data/blob/7606917390b43dc02b251d88dbceed6296a919fc/LICENSE); bản sao ở `CISA-KEV-LICENSE`.

Tệp JSON được giữ nguyên byte để SHA-256 kiểm tra chính xác. `rag_sec/kev.py` từ chối tệp bị thay đổi hoặc số lượng/ID bản ghi không hợp lệ. Mã benchmark chỉ dùng các trường CVE ID, vendor, product, vulnerability name, short description và required action. Các liên kết tới bên thứ ba trong dữ liệu có điều khoản riêng; dự án không sao chép nội dung từ các trang đó. CISA/DHS không tài trợ hay xác nhận dự án.
