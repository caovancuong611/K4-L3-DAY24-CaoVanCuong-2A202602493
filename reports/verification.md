# Verification — điền trước khi nộp

- **OS / Python / Gitleaks version:** Windows 11 + WSL2 Ubuntu; Python 3.14.4 (venv `.venv`); Gitleaks 8.30.1 (binary Linux x64, release chính thức).

- **`python -m pytest tests/ -q`:** `33 passed`
  - `test_injection.py` 8/8 (4 biến thể × `support_l1`, `dpo`), `test_pii.py` (2), `test_policy.py` (4), `test_ledger.py` (3), `test_obo.py` (5), `test_split.py` (1), `test_supply_chain.py` (3), `test_scaffold_dispatch.py` (4), `test_check_lure_cli.py` (3).
  - `python -m pytest tests/test_pii.py -s` → `gold=118 pred=118 tp=118`, `precision=1.000 recall=1.000` trên `tests/vn_pii_testset.jsonl` (test set synthetic, định dạng đồng nhất — chưa đo trên dữ liệu có SĐT/STK viết cách quãng hoặc ngữ cảnh khác).
  - `python -m agent.check_lure corpus/ticket-90*.md` → `4/4 lure sẵn sàng`.

- **`pre-commit run --all-files`:** `Detect hardcoded secrets....Passed` (hook `gitleaks-system`, `rev: v8.30.1`, `pass_filenames: false`).

- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` → `True` (45 dòng, mọi dòng có `reason`).

- **Các lỗi còn lại:**
  1. (đã xử lý) Lure biến thể 2–4 đã có, `check_lure` 4/4.
  2. (đã xử lý) `agent/pii.py` đã implement, recall 1.000.
  3. **Khác với CHECKPOINTS.md:** `gitleaks git --config .gitleaks.toml --redact .` báo `leaks found: 1` (commit `1bdd849`, rule `lab24-synthetic-token`) nhưng exit code là **0**, không phải 1 như tài liệu mô tả. Tái hiện: trong WSL2 Ubuntu, repo ở `/mnt/c/...`, Gitleaks 8.30.1, chạy `gitleaks git --config .gitleaks.toml --redact . ; echo $?` → `0`; thêm `--exit-code 1` vẫn trả `0`. Report JSON (`--report-path`) có đúng 1 finding.
  4. Hook pre-commit được cài từ WSL (`.git/hooks/pre-commit` trỏ tới Python trong `.venv` Linux) — commit phải chạy trong WSL, commit từ Git for Windows sẽ không chạy được hook.
