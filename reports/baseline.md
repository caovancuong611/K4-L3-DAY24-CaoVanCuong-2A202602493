# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
   **Chưa.** `agent/loop.py` → `_naive_loop()` (dòng 27–54) không sinh `agent_id`/`run_id`, không gắn principal vào bất kỳ tool call nào. `run_once()` có nhận `principal_id` (dòng 58) nhưng khi rơi về baseline ở dòng 74 thì gọi `_naive_loop(message, llm)` — `principal_id` bị bỏ đi, nên `--as support_l1` hay `--as dpo` cho cùng một hành vi.

2. Ai cho phép `http_post`? Dẫn file/hàm:
   **Không ai.** Trong `agent/loop.py` → `_naive_loop()`, `tools.http_post(injected.target_url, ...)` (dòng 44) chạy ngay khi `llm.find_injection()` (dòng 34) thấy chỉ thị trong text của corpus — tức là chính nội dung untrusted của attacker "cho phép". Không có PEP/`policy.check()` trước call. Thứ duy nhất chặn là allowlist cứng host/port trong `agent/tools.py` → `http_post()` (dòng 76–83), vốn chỉ để lab không ra Internet, không xét classification hay purpose. URL đích và `customer_ids` cũng lấy thẳng từ free text (`agent/llm.py` → `find_injection()`, dòng 161–163).

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
   **Chỉ ở phía nhận.** `sink/sink.py` → `make_handler().do_POST()` (dòng 42–50) ghi body vào `reports/sink.log`. Phía agent không có ledger/audit log nào (`_naive_loop()` không gọi `agent.ledger.append()`), nên không có bản ghi ai/run nào đã đọc `read_customer` (dòng 39) và gửi đi, với lý do gì. Nếu attacker trỏ ra đích ngoài thì sẽ không còn bằng chứng nào.
