"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    """Nguồn tin cậy mô phỏng — chỉ tra principal ở đây, không tin input khác."""
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def _parse_expiry(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed.tzinfo is None:  # không đoán múi giờ: coi như không hợp lệ
        return None
    return parsed


def check(context: PolicyContext) -> tuple[bool, str]:
    """PEP: trả (allow, reason). Mọi nhánh đều có reason non-empty.

    Thứ tự: rule tối thiểu trước (không principal nào vượt được), rồi TTL,
    rồi OBO (principal -> tool -> agent scope -> parent scope -> purpose).
    Mặc định là deny nếu thiếu dữ kiện.
    """
    # 1. Rule tối thiểu bắt buộc: dữ liệu restricted không bao giờ đi kèm egress.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, ("deny: data_classification=restricted với egress_enabled=True "
                       f"(tool={context.requested_tool or '?'}, agent={context.agent_owner})")

    if context.data_classification not in {"public", "internal", "restricted"}:
        return False, f"deny: data_classification không hợp lệ: {context.data_classification!r}"

    # 2. TTL của run: thiếu, sai định dạng hoặc đã hết hạn đều deny.
    expiry = _parse_expiry(context.expires_at)
    if expiry is None:
        return False, f"deny: expires_at thiếu hoặc không phải ISO-8601 có timezone: {context.expires_at!r}"
    if expiry <= datetime.now(timezone.utc):
        return False, f"deny: run đã hết hạn lúc {context.expires_at}"

    # 3. OBO: principal phải có trong nguồn tin cậy.
    principal = _load_principals().get(context.principal_id)
    if principal is None:
        return False, f"deny: principal không xác định: {context.principal_id!r}"

    tool = context.requested_tool
    if not tool:
        return False, "deny: thiếu requested_tool"
    if tool not in principal.get("allowed_tools", []):
        return False, (f"deny: principal {context.principal_id} (role={principal.get('role')}) "
                       f"không có quyền {tool}")
    if tool not in context.agent_scopes:
        return False, f"deny: {tool} nằm ngoài agent_scopes {list(context.agent_scopes)} của {context.agent_owner}"
    if context.delegation_depth > 0 and tool not in context.parent_scopes:
        return False, (f"deny: agent con (depth={context.delegation_depth}) không được vượt "
                       f"parent_scopes {list(context.parent_scopes)} để gọi {tool}")
    if context.request_purpose not in principal.get("purposes", []):
        return False, (f"deny: purpose {context.request_purpose!r} không nằm trong purposes "
                       f"của principal {context.principal_id}")

    return True, (f"allow: {tool} cho principal {context.principal_id} "
                  f"(purpose={context.request_purpose}, classification={context.data_classification}, "
                  f"egress={context.egress_enabled}, depth={context.delegation_depth})")
