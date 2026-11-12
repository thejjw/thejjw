"""MiniMax token-plan allowances.

One request covers every model. Each row carries two windows -- the current
interval and the current week -- expressed as *remaining* percent, which is
inverted here because the shared contract reports used percent.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..contract import RESET_API, UsageReport, Window, parse_timestamp
from ..http import get_json

URL = "https://www.minimax.io/v1/token_plan/remains"
SOURCE = "token_plan_api"


def _remaining_to_used(value: float | int | str | None) -> float | None:
    """Invert a remaining percentage into a used percentage."""
    try:
        return None if value is None else max(0.0, 100 - float(value))
    except (TypeError, ValueError):
        return None


def parse(doc: dict, *, fetched_at: datetime | None = None) -> UsageReport:
    """Build one report covering every model row in the response."""
    fetched = fetched_at or datetime.now(timezone.utc)
    windows: list[Window] = []
    for row in doc.get("model_remains") or []:
        name = str(row.get("model_name") or "model")
        interval_total = row.get("current_interval_total_count") or 0
        weekly_total = row.get("current_weekly_total_count") or 0
        windows.append(
            Window(
                label=f"{name} interval",
                used_percent=_remaining_to_used(row.get("current_interval_remaining_percent")),
                resets_at=parse_timestamp(row.get("end_time")),
                resets_source=RESET_API,
                detail=(
                    f"{row.get('current_interval_usage_count')}/{interval_total}"
                    if interval_total
                    else None
                ),
            )
        )
        windows.append(
            Window(
                label=f"{name} week",
                used_percent=_remaining_to_used(row.get("current_weekly_remaining_percent")),
                resets_at=parse_timestamp(row.get("weekly_end_time")),
                resets_source=RESET_API,
                detail=(
                    f"{row.get('current_weekly_usage_count')}/{weekly_total}" if weekly_total else None
                ),
            )
        )
    return UsageReport(
        provider="minimax",
        source=SOURCE,
        fetched_at=fetched,
        windows=windows,
    )


def fetch(api_key: str, *, fetched_at: datetime | None = None) -> UsageReport:
    """Query the token-plan endpoint and build the report."""
    doc = get_json(
        URL,
        {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    return parse(doc, fetched_at=fetched_at)
