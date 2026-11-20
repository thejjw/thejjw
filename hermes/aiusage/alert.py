"""Select weekly quota windows that reset soon and render the alert message.

Pure function of the reports plus an injected ``now``: no network, no clock
reads, no provider knowledge beyond the window labels. That keeps the alert
testable against the same saved fixtures as the daily digest.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .contract import UsageReport, Window
from .render import KST, PROVIDER_ORDER, format_percent, provider_label

# Weekly windows worth an alert, per provider, matched case-insensitively. The
# first hit wins. A mapped provider with no label match falls back to the
# generic pattern below, so a provider that renames its window still alerts.
WEEKLY_LABELS: dict[str, tuple[str, ...]] = {
    "anthropic": ("current week",),
    "opencode-go": ("weekly",),
    "kimi": ("weekly",),
    "minimax": ("general week", "video week"),
}

_WEEK_PATTERN = re.compile(r"week", re.IGNORECASE)


def _weekly_windows(provider: str, windows: list[Window]) -> list[Window]:
    """Pick the provider's weekly quota window(s) out of all its windows."""
    labels = WEEKLY_LABELS.get(provider)
    if labels:
        matched = [w for w in windows if w.label.strip().lower() in labels]
        if matched:
            return matched
    return [w for w in windows if _WEEK_PATTERN.search(w.label)]


def _days_until(window: Window, now: datetime) -> int | None:
    """Whole KST calendar days from ``now`` to the reset, or None if unset."""
    if window.resets_at is None:
        return None
    return (window.resets_at.astimezone(KST).date() - now.astimezone(KST).date()).days


def _provider_rank(provider: str) -> int:
    """Canonical provider order, so the alert reads in the digest's order."""
    try:
        return PROVIDER_ORDER.index(provider)
    except ValueError:
        return len(PROVIDER_ORDER)


def due_windows(
    reports: list[UsageReport],
    now: datetime | None = None,
    within: tuple[int, ...] = (1, 2),
) -> list[tuple[int, UsageReport, Window]]:
    """Windows resetting in ``within`` days, deduped per provider by reset time.

    A provider reporting several weekly windows that reset together (MiniMax's
    general and video weeks) yields one entry, keeping the first label.
    """
    now = now or datetime.now(timezone.utc)
    wanted = set(within)
    seen: set[tuple[str, datetime]] = set()
    found: list[tuple[int, UsageReport, Window]] = []
    for report in reports:
        if not report.available:
            continue
        for window in _weekly_windows(report.provider, report.windows):
            resets_at = window.resets_at
            if resets_at is None:
                continue
            days = _days_until(window, now)
            if days is None or days not in wanted:
                continue
            key = (report.provider, resets_at)
            if key in seen:
                continue
            seen.add(key)
            found.append((days, report, window))
    found.sort(key=lambda item: (-item[0], _provider_rank(item[1].provider)))
    return found


def _render_entry(report: UsageReport, window: Window) -> str:
    """Render one alert line: provider, window, usage, reset time."""
    parts = [provider_label(report.provider), window.label]
    percent = format_percent(window.used_percent)
    if percent is not None:
        parts.append(f"{percent} used")
    if window.detail:
        parts.append(window.detail)
    if window.resets_at is not None:
        parts.append(f"resets {window.resets_at.astimezone(KST):%m-%d %H:%M} KST")
    return " · ".join(parts)


def render_alert(
    reports: list[UsageReport],
    now: datetime | None = None,
    within: tuple[int, ...] = (1, 2),
) -> str:
    """Render the reset alert, or an empty string when nothing is due."""
    entries = due_windows(reports, now=now, within=within)
    if not entries:
        return ""
    now = now or datetime.now(timezone.utc)
    header = f"Reset alert — {now.astimezone(KST):%m-%d %H:%M} KST"
    blocks: list[str] = []
    for days in sorted({days for days, _, _ in entries}, reverse=True):
        lines = [f"{days} day{'s' if days != 1 else ''} to reset:"]
        lines += [
            "  " + _render_entry(report, window)
            for day, report, window in entries
            if day == days
        ]
        blocks.append("\n".join(lines))
    return "\n\n".join([header, *blocks])
