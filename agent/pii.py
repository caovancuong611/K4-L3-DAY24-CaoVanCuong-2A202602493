"""Small regex based PII gate for the synthetic Vietnamese lab corpus."""
from __future__ import annotations

import re


_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_CCCD = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE = re.compile(r"(?<!\d)0\d{9,10}(?!\d)")
_ACCOUNT = re.compile(r"(?<!\d)\d{8,16}(?!\d)")
_ACCOUNT_LABEL = re.compile(r"(?:STK|số\s+tài\s+khoản|tài\s+khoản)\s*[:#-]?\s*$", re.IGNORECASE)


def detect(text: str) -> list[dict]:
    """Return non-overlapping PII spans using offsets into the original text."""
    candidates: list[dict] = []
    for kind, pattern in (("EMAIL", _EMAIL), ("VN_CCCD", _CCCD), ("VN_PHONE", _PHONE)):
        candidates.extend({"type": kind, "start": m.start(), "end": m.end()} for m in pattern.finditer(text))
    for match in _ACCOUNT.finditer(text):
        if _ACCOUNT_LABEL.search(text[max(0, match.start() - 32):match.start()]):
            candidates.append({"type": "VN_BANK_ACCOUNT", "start": match.start(), "end": match.end()})

    # Prefer the most specific labeled/typed recognizer when spans overlap.
    priority = {"VN_BANK_ACCOUNT": 0, "EMAIL": 1, "VN_CCCD": 2, "VN_PHONE": 3}
    accepted: list[dict] = []
    for candidate in sorted(candidates, key=lambda e: (e["start"], e["end"] - e["start"], priority[e["type"]])):
        if any(candidate["start"] < item["end"] and item["start"] < candidate["end"] for item in accepted):
            continue
        accepted.append(candidate)
    return sorted(accepted, key=lambda e: e["start"])


def redact(text: str) -> str:
    for entity in reversed(detect(text)):
        text = text[:entity["start"]] + f"[REDACTED_{entity['type']}]" + text[entity["end"]:]
    return text