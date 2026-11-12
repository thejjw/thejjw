"""DeepSeek: prepaid balance, not a quota window.

The upstream PowerShell function also projects a token budget from a 12-row
pricing table; that projection is deliberately not ported yet because the
prices rot and cannot be verified from the response itself. Balances only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..contract import UsageReport
from ..http import get_json

URL = "https://api.deepseek.com/user/balance"
SOURCE = "balance_api"


def parse(doc: dict, *, fetched_at: datetime | None = None) -> UsageReport:
    """Build the report from a ``/user/balance`` response."""
    fetched = fetched_at or datetime.now(timezone.utc)
    details: list[str] = []
    for balance in sorted(doc.get("balance_infos") or [], key=lambda b: str(b.get("currency", ""))):
        currency = balance.get("currency", "?")
        total = float(balance.get("total_balance") or 0)
        line = f"{currency} {total:.2f}"
        granted = float(balance.get("granted_balance") or 0)
        if granted:
            line += f" (incl. {granted:.2f} granted)"
        details.append(line)
    if not details:
        details.append("no balance reported")

    note = "prepaid account, no reset window"
    if doc.get("is_available") is False:
        note = "account cannot make API calls (prepaid, no reset window)"
    return UsageReport(
        provider="deepseek",
        source=SOURCE,
        fetched_at=fetched,
        details=details,
        note=note,
    )


def fetch(api_key: str, *, fetched_at: datetime | None = None) -> UsageReport:
    """Query the balance endpoint and build the report."""
    doc = get_json(URL, {"Authorization": f"Bearer {api_key}", "Accept": "application/json"})
    return parse(doc, fetched_at=fetched_at)
