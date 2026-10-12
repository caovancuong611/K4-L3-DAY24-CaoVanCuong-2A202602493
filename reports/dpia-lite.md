# DPIA-lite — điền trong checkpoint 5

> Toàn bộ dữ liệu là **synthetic** (`data/customers.json`, `corpus/`). Đây là đánh giá cho hệ thống mô phỏng của lab, không phải DPIA cho hệ thống production.

1. **Loại dữ liệu và phân loại:**
   - `corpus/*.md` (ticket hỗ trợ): **internal**, nhưng là **untrusted** — attacker có thể cài chỉ thị vào nội dung. Một số ticket chứa STK/SĐT synthetic trong free text.
   - `data/customers.json`: **restricted** — họ tên, CCCD, SĐT, STK, email, `related_tickets`. CCCD và STK là dữ liệu định danh/tài chính nhạy cảm.
   - `data/principals.json`: cấu hình quyền mô phỏng (nguồn tin cậy cho OBO).
   - `reports/ledger.jsonl`: metadata audit, không chứa PII thô (tham số chỉ lưu dạng `args_hash`).

2. **Mục đích xử lý và principal:**
   - `summarize-tickets`: Run A tìm và tóm tắt ticket — mọi principal có `search_docs`.
   - `support-reply`: Run B đọc hồ sơ khách gắn với ticket — chỉ `dpo` (có `read_customer` và purpose này). `support_l1` không có `read_customer` nên bị deny trước khi đọc. `billing` có `read_customer` nhưng không có purpose `support-reply` nên cũng bị deny.
   - Không mục đích nào cho phép gửi record khách hàng ra ngoài.

3. **Dữ liệu đi qua những run/tool nào, endpoint nào:**
   - **Run A** (`lab24-agent/run-a`, scope `search_docs`): đọc `corpus/`. Chỉ chuyển sang Run B danh sách `int` ticket id lấy từ tên file.
   - **Run B** (`lab24-agent/run-b`, scope `read_customer`): map ticket id → customer id qua `related_tickets`, rồi `read_customer`. Record nằm trong bộ nhớ của run, không được trả cho người dùng (câu trả lời CLI chỉ là tóm tắt danh sách ticket).
   - **Egress** (`lab24-agent/egress`, scope `http_post`): chỉ được thử khi mock phát hiện chỉ thị; body chứa record restricted nên PEP deny. Endpoint duy nhất có thể chạm là sink localhost `http://127.0.0.1:10024/*` (allowlist cứng trong `agent/tools.py`).
   - **Ledger**: `reports/ledger.jsonl` (local file).

4. **Bằng chứng deny/allow và giới hạn của mock:**
   - Trước containment: `reports/attack-before.log` chứa record synthetic của `KH-000999` bị POST tới `/reconcile`.
   - Sau containment (`--as dpo`, cùng query): `reports/attack-after.log` rỗng (0 byte); `reports/ledger.jsonl` dòng 23 là `http_post` **deny** với reason `restricted với egress_enabled=True`, `on_behalf_of: dpo`. Với `--as support_l1`, dòng 25–45 là `read_customer` deny. `verify()` trên ledger trả `True`.
   - **Giới hạn:**
     - Mock LLM deterministic chỉ nhận chỉ thị theo danh sách marker; model thật có thể bị điều khiển bằng cách khác, nhưng containment kiến trúc (split + PEP) không phụ thuộc việc phát hiện.
     - `--as` chỉ chọn principal mô phỏng, không có xác thực danh tính.
     - Run B với `dpo` đọc mọi khách gắn với ticket khớp query, nhiều hơn mức cần cho một bản tóm tắt — rủi ro tối thiểu hoá còn mở.
     - Ledger là hash chain trong một file: phát hiện sửa dòng, không phát hiện cắt đuôi/viết lại toàn bộ nếu không có mốc tin cậy bên ngoài.
     - Lure 2–4 (`ticket-902`…`904b`) do sinh viên viết; cả 4 biến thể bị chặn dưới cả hai principal (`tests/test_injection.py` 8/8), chi tiết trong `injection-corpus.md`.
