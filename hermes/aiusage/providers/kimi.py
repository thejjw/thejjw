"""Kimi Code membership quota.

The endpoint returns three overlapping views of the same quotas: a top-level
``usage`` (weekly), a ``limits`` array (window + detail), and a newer ``usages``
object keyed by window (``limit_5h``, ``limit_7d``). ``usages`` carries the
ratio directly, so it wins per window; the legacy views fill only the windows
the modern view does not cover, so mixed responses keep every available window.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from ..contract import RESET_API, RESET_RELATIVE, UsageReport, Window, parse_timestamp
from ..http import get_json

DEFAULT_BASE = "https://api.kimi.com/coding/v1"
SOURCE = "membership_api"


def _window_label(duration: int | None, unit: str | None) -> str:
    """Turn (duration, TIME_UNIT_*) into a short label such as '5h' or '7d'."""
    if not duration:
        return "quota"
    unit = (unit or "").upper()
    if "MINUTE" in unit:
        return f"{duration // 60}h" if duration % 60 == 0 else f"{duration}m"
    if "HOUR" in unit:
        return f"{duration}h"
    if "DAY" in unit:
        return f"{duration}d"
    return f"{duration} {unit.lower() or 'units'}"


def _window_identity(duration: int | None, unit: str | None) -> str:
    """Canonical identity that merges the overlapping legacy views: 300
    minutes and 5 hours are the same window, as are 7 days and 168 hours.
    Durations without a modern equivalent keep their label as identity
    instead of collapsing into one shared bucket."""
    label = _window_label(duration, unit)
    if label in ("7d", "168h") or (
        (unit or "").upper().startswith("TIME_UNIT_WEEK") and duration == 1
    ):
        return "weekly"
    return label


def _used_percent(limit: float | None, remaining: float | None) -> float | None:
    """Derive a used percentage from a limit and its remainder."""
    if not limit or remaining is None:
        return None
    return max(0.0, 100 * (limit - remaining) / limit)


def parse(doc: dict, *, fetched_at: datetime | None = None) -> UsageReport:
    """Build the report from a ``/usages`` response."""
    fetched = fetched_at or datetime.now(timezone.utc)
    windows: list[Window] = []
    details: list[str] = []

    # The modern ``usages`` view wins for the windows it covers; the identities
    # recorded here keep the legacy views from duplicating them.
    seen: set[str] = set()
    usages = doc.get("usages") or {}
    if isinstance(usages, dict) and usages:
        for key, label, identity in (("limit_5h", "5h", "5h"), ("limit_7d", "weekly", "weekly")):
            block = usages.get(key) or {}
            if not block:
                continue
            ratio = _as_float(block.get("used_ratio"))
            windows.append(
                Window(
                    label=label,
                    used_percent=None if ratio is None else ratio * 100,
                    resets_at=parse_timestamp(block.get("reset_time")),
                    resets_source=RESET_API,
                )
            )
            seen.add(identity)

    # Legacy views now fill only the gaps, one identity at a time: a response
    # carrying a single modern window keeps its legacy counterpart instead of
    # losing it, while an identity the modern view already covered is skipped.
    usage = doc.get("usage") or {}
    if usage and "weekly" not in seen:
        windows.append(
            Window(
                label=str(usage.get("name") or usage.get("title") or "weekly"),
                used_percent=_used_percent(
                    _as_float(usage.get("limit")), _as_float(usage.get("remaining"))
                ),
                resets_at=parse_timestamp(usage.get("resetTime") or usage.get("reset_at")),
                resets_source=RESET_API,
            )
        )
        seen.add("weekly")
    for limit in doc.get("limits") or []:
        detail = limit.get("detail") if isinstance(limit.get("detail"), dict) else limit
        window_meta = detail.get("window") or limit.get("window") or {}
        # Entries without window metadata carry no identity, so they can never
        # be deduplicated safely and are always kept (previous behavior).
        identity = None
        if window_meta.get("duration"):
            identity = _window_identity(window_meta.get("duration"), window_meta.get("timeUnit"))
            if identity in seen:
                continue
        reset_at = parse_timestamp(
            detail.get("resetTime")
            or detail.get("reset_at")
            or detail.get("resetAt")
            or detail.get("reset_time")
        )
        source = RESET_API
        if reset_at is None:
            seconds = _as_float(detail.get("reset_in") or detail.get("ttl"))
            if seconds:
                reset_at = fetched + timedelta(seconds=seconds)
                source = RESET_RELATIVE
        windows.append(
            Window(
                label=_window_label(window_meta.get("duration"), window_meta.get("timeUnit")),
                used_percent=_used_percent(
                    _as_float(detail.get("limit")), _as_float(detail.get("remaining"))
                ),
                resets_at=reset_at,
                resets_source=source if reset_at else None,
            )
        )
        if identity is not None:
            seen.add(identity)

    wallet = doc.get("boosterWallet")
    if isinstance(wallet, dict):
        balance = wallet.get("balance") or {}
        units = _as_float(balance.get("amount"))
        if units and str(balance.get("type", "")).upper() == "BOOSTER":
            # Fixed point: 1,000,000 units = 1 cent.
            details.append(f"booster {units / 1e6 / 100:.2f}")

    return UsageReport(
        provider="kimi",
        source=SOURCE,
        fetched_at=fetched,
        windows=windows,
        details=details,
    )


def _as_float(value: float | int | str | None) -> float | None:
    """Coerce numeric strings to float, tolerating junk."""
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def fetch(api_key: str, *, fetched_at: datetime | None = None) -> UsageReport:
    """Query the membership endpoint and build the report."""
    base = os.environ.get("KIMI_CODE_BASE_URL", DEFAULT_BASE).rstrip("/")
    doc = get_json(
        f"{base}/usages",
        {"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
    )
    return parse(doc, fetched_at=fetched_at)
