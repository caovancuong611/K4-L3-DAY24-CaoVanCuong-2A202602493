# Secret giả trong lịch sử Git — điền trong checkpoint 4

- **Scanner và phiên bản:** Gitleaks 8.30.1 (`gitleaks version` → `8.30.1`), binary Linux x64 từ release chính thức, chạy trong WSL2 Ubuntu. Cấu hình `.gitleaks.toml` (`useDefault = true` + rule riêng của lab).

- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`, "chore: seed student lab with synthetic secret exercise"). File bị xoá ở commit sau `ece6ca4` (`git log --diff-filter=D -- lab-fake-secret.txt`).

- **File, rule và kết quả quét lịch sử:** `gitleaks git --config .gitleaks.toml --redact --verbose .` → `4 commits scanned`, `leaks found: 1`:
  - File: `lab-fake-secret.txt`, dòng 1
  - RuleID: `lab24-synthetic-token` (regex `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`)
  - Fingerprint: `1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1`
  - Giá trị đã được `--redact`, không chép token vào báo cáo.
  - Đây là token **giả, vô hiệu** do đề bài cài sẵn, không phải sự cố bảo mật thật.

- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → `no leaks found`. Hook `pre-commit run --all-files` (`gitleaks-system`, pin `rev: v8.30.1`) → `Passed`.

- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi / rotate ngay** credential ở hệ thống phát hành (coi như đã lộ từ thời điểm commit được push), cấp credential mới qua secret manager, không qua repo.
  2. Rà log truy cập của hệ thống đó trong khoảng từ commit `1bdd849` đến lúc thu hồi để tìm việc sử dụng trái phép.
  3. Sau khi đã rotate, mới cân nhắc viết lại lịch sử (`git filter-repo`) và yêu cầu mọi bản clone/fork cập nhật; ghi incident và thông báo theo quy trình nội bộ.
  4. Thêm rule/hook để chặn tái diễn (đã có `.pre-commit-config.yaml`).

- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Xoá file ở commit sau không xoá nó khỏi lịch sử: bất kỳ ai có bản clone, fork, cache CI hay mirror vẫn `git show 1bdd849:lab-fake-secret.txt` được. Kể cả viết lại lịch sử cũng không thu hồi được các bản đã bị sao chép — chỉ **rotate** mới làm credential cũ vô giá trị.
  - Pin dependency bằng hash (`requirements.lock`, `--require-hashes`) chống package bị thay thế/giả mạo trong chuỗi cung ứng; nó không liên quan gì tới secret đã lộ.
  - Hook pre-commit chỉ chặn secret **mới** trước khi commit (và có thể bị bỏ qua bằng `--no-verify` hoặc ở máy chưa cài hook); nó không sửa được lịch sử đã có. Đây là control phòng ngừa, không phải control khắc phục.
