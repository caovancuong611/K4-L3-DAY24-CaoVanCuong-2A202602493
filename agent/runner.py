"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
RUN_TTL = timedelta(minutes=5)
# Agent cha (orchestrator, depth 0) giữ quyền tối đa; mỗi run con chỉ nhận
# đúng một chân của trifecta qua agent_scopes riêng.
ORCHESTRATOR_SCOPES = ("search_docs", "read_customer", "http_post")
RUN_A_SCOPES = ("search_docs",)
RUN_B_SCOPES = ("read_customer",)
EGRESS_SCOPES = ("http_post",)

_TICKET_FILE_RE = re.compile(r"^ticket-(\d+)[a-z]?\.md$")


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def _args_hash(args: dict) -> str:
    canonical = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class _Run:
    """Một run con có identity riêng: agent_id, run_id, TTL, scope."""

    def __init__(self, name: str, principal_id: str, scopes: tuple[str, ...],
                 ledger_path: Path, expires_at: str):
        self.agent_id = f"{AGENT_ID}/{name}"
        self.run_id = f"{name}-{uuid.uuid4().hex[:12]}"
        self.principal_id = principal_id
        self.scopes = scopes
        self.ledger_path = ledger_path
        self.expires_at = expires_at

    def gate(self, tool: str, args: dict, classification: str, purpose: str,
             egress: bool) -> bool:
        """Hỏi PEP TRƯỚC KHI gọi tool, ghi ledger cả allow lẫn deny."""
        context = policy.PolicyContext(
            data_classification=classification,
            request_purpose=purpose,
            agent_owner=self.agent_id,
            delegation_depth=1,
            egress_enabled=egress,
            principal_id=self.principal_id,
            requested_tool=tool,
            agent_scopes=self.scopes,
            parent_scopes=ORCHESTRATOR_SCOPES,
            expires_at=self.expires_at,
        )
        allow, reason = policy.check(context)
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "on_behalf_of": self.principal_id,
            "expires_at": self.expires_at,
            "tool": tool,
            "args_hash": _args_hash(args),  # không ghi PII thô vào ledger
            "classification": classification,
            "purpose": purpose,
            "egress": egress,
            "decision": "allow" if allow else "deny",
            "reason": reason,
        }, self.ledger_path)
        return allow


def _ticket_ids(docs: list[dict]) -> list[int]:
    """Chỉ lấy số từ TÊN FILE — không đọc nội dung document."""
    ids = set()
    for doc in docs:
        match = _TICKET_FILE_RE.match(doc["id"])
        if match:
            ids.add(int(match.group(1)))
    return sorted(ids)


def _customers_for_tickets(ticket_ids: list[int]) -> list[str]:
    """Map ticket_id -> customer_id qua related_tickets (nguồn tin cậy)."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    wanted = set(ticket_ids)
    return [str(c["customer_id"]) for c in customers
            if wanted.intersection(c.get("related_tickets", []))]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    ledger_path = (Path(log_dir) / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    expires_at = (datetime.now(timezone.utc) + RUN_TTL).isoformat()

    # ── Run A: untrusted content. Không private data, không egress. ──
    run_a = _Run("run-a", principal_id, RUN_A_SCOPES, ledger_path, expires_at)
    docs: list[dict] = []
    if run_a.gate("search_docs", {"query": message}, "internal", "summarize-tickets", egress=False):
        docs = tools.search_docs(message)
    ticket_ids = _ticket_ids(docs)  # boundary A -> B: chỉ list[int]
    injected = llm.find_injection("\n\n".join(d["text"] for d in docs)) if docs else None

    # ── Run B: private data. Input duy nhất là ticket_ids đã typed. ──
    run_b = _Run("run-b", principal_id, RUN_B_SCOPES, ledger_path, expires_at)
    records: list[dict] = []
    for customer_id in _customers_for_tickets(ticket_ids):
        if not run_b.gate("read_customer", {"customer_id": customer_id}, "restricted",
                          "support-reply", egress=False):
            continue
        try:
            records.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    # ── Egress: model "muốn" POST theo chỉ thị trong tài liệu. Yêu cầu đó
    # vẫn phải qua PEP; body chứa record restricted nên rule tối thiểu deny.
    # URL của attacker chỉ đi vào args_hash, không bao giờ được gọi khi deny.
    if injected is not None and records:
        egress = _Run("egress", principal_id, EGRESS_SCOPES, ledger_path, expires_at)
        body = {"records": records}
        if egress.gate("http_post", {"url": injected.target_url, "body": body},
                       "restricted", "support-reply", egress=True):
            tools.http_post(injected.target_url, body)

    return llm.summarize(docs)
