"""Render merged usage reports into the plain-text message sent to Telegram.

Rendering is a pure function of the reports plus an injected ``now``: no network,
no clock reads, no provider knowledge beyond display names. That keeps the whole
output layer testable against saved fixtures.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .contract import UsageReport, Window

KST = ZoneInfo("Asia/Seoul")

# Display order and names; unknown providers fall through alphabetically after these.
PROVIDER_ORDER = ("openai-codex", "anthropic", "opencode-go", "zai", "kimi", "minimax", "deepseek")
PROVIDER_LABELS = {
    "openai-codex": "Codex",
    "anthropic": "Anthropic",
    "opencode-go": "OpenCodeGo",
    "zai": "Z.AI",
    "kimi": "Kimi",
    "minimax": "MiniMax",
    "deepseek": "DeepSeek",
}


def provider_label(provider: str) -> str:
    """Human-readable provider name used in the message."""
    return PROVIDER_LABELS.get(provider, provider)


def format_percent(value: float | None) -> str | None:
    """Format a used-percentage without trailing zeros, keeping sub-1% detail."""
    if value is None:
        return None
    text = f"{value:.2f}" if abs(value) < 10 else f"{value:.0f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return f"{text}%"


def format_tokens(value: float | None) -> str:
    """Format a token count compactly: '5.79M', '12.4K', '894'."""
    if value is None:
        return "-"
    if value >= 1e9:
        return f"{value / 1e9:.2f}B"
    if value >= 1e6:
        return f"{value / 1e6:.2f}M"
    if value >= 1e3:
        return f"{value / 1e3:.2f}K"
    return f"{value:.0f}"


def format_countdown(delta: timedelta) -> str:
    """Compact remaining-time label: 'in 6d 1h', 'in 5h 12m', 'in 13m', or 'passed'."""
    seconds = int(delta.total_seconds())
    if seconds <= 0:
        return "passed"
    minutes = seconds // 60
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    if days:
        return f"in {days}d {hours}h"
    if hours:
        return f"in {hours}h {mins}m" if mins else f"in {hours}h"
    return f"in {mins}m"


def format_reset(window: Window, now: datetime) -> str:
    """Render a window's reset time in KST, or say plainly why there isn't one."""
    if window.resets_at is not None:
        local = window.resets_at.astimezone(KST)
        countdown = format_countdown(window.resets_at - now)
        return f"resets {local:%m-%d %H:%M} KST ({countdown})"
    if window.reset_note:
        return f"reset not reported ({window.reset_note})"
    return "reset n/a"


def build_previous_lookup(
    reports: list[UsageReport],
) -> dict[tuple[str, str, datetime], float]:
    """Index a previous run's used-percent by (provider, label, reset time).

    A window without a reset time cannot be proven to be the same quota period,
    so it is left out rather than compared against a value that has rolled over.
    """
    lookup: dict[tuple[str, str, datetime], float] = {}
    for report in reports:
        if not report.available:
            continue
        for window in report.windows:
            if window.resets_at is None or window.used_percent is None:
                continue
            lookup[(report.provider, window.label, window.resets_at)] = window.used_percent
    return lookup


def _previous_percent(
    window: Window,
    previous: dict[tuple[str, str, datetime], float] | None,
    provider: str | None,
) -> str | None:
    """Formatted previous used-percent for the same window, or None."""
    if previous is None or provider is None or window.resets_at is None:
        return None
    value = previous.get((provider, window.label, window.resets_at))
    return None if value is None else format_percent(value)


def render_window(
    window: Window,
    now: datetime,
    previous: dict[tuple[str, str, datetime], float] | None = None,
    provider: str | None = None,
) -> str:
    """Render one window as '<label> <pct>% used (was <pct>%) · <reset>'.

    The ``was`` clause appears only when the previous report carried this same
    window in the same quota period (same provider, label and reset time).
    """
    parts = [window.label]
    percent = format_percent(window.used_percent)
    was = _previous_percent(window, previous, provider)
    if percent is not None:
        parts.append(f"{percent} used" + (f" (was {was})" if was else ""))
    elif was:
        parts.append(f"(was {was})")
    if window.detail:
        parts.append(window.detail)
    parts.append(format_reset(window, now))
    return " · ".join(parts)


def render_report(
    report: UsageReport,
    now: datetime,
    previous: dict[tuple[str, str, datetime], float] | None = None,
) -> list[str]:
    """Render one provider as a heading line plus indented detail lines."""
    heading = provider_label(report.provider)
    if report.plan:
        heading = f"{heading} · {report.plan}"
    lines = [heading]
    for window in report.windows:
        lines.append("  " + render_window(window, now, previous, report.provider))
    for detail in report.details:
        lines.append("  " + detail)
    if report.note:
        lines.append("  " + report.note)
    return lines


def order_reports(reports: list[UsageReport]) -> list[UsageReport]:
    """Sort by the canonical provider order, then alphabetically for anything new."""

    def key(report: UsageReport) -> tuple[int, str]:
        try:
            return (PROVIDER_ORDER.index(report.provider), "")
        except ValueError:
            return (len(PROVIDER_ORDER), report.provider)

    return sorted(reports, key=key)


def render_message(
    reports: list[UsageReport],
    now: datetime | None = None,
    timezone_label: str = "KST",
    previous: list[UsageReport] | None = None,
) -> str:
    """Render the full message: KST header, one block per provider, unavailability footer.

    When ``previous`` is supplied, each window that also existed in that run
    carries a ``(was X%)`` clause and a legend under the header explains it.
    """
    now = now or datetime.now(timezone.utc)
    header = f"AI usage — {now.astimezone(KST):%m-%d %H:%M} {timezone_label}"
    legend = _previous_legend(previous or [], timezone_label)
    lookup = build_previous_lookup(previous or [])

    blocks: list[str] = []
    missing: list[str] = []
    for report in order_reports(reports):
        if not report.available:
            reason = report.unavailable_reason or "no data"
            missing.append(f"{provider_label(report.provider)} ({reason})")
            continue
        blocks.append("\n".join(render_report(report, now, lookup)))

    body = "\n\n".join(blocks) if blocks else "No provider reported usage."
    message = f"{header}\n{legend}\n\n{body}" if legend else f"{header}\n\n{body}"
    if missing:
        label = "unavailable" if len(missing) == 1 else "unavailable"
        message += f"\n\n{len(missing)} {label}: " + ", ".join(missing)
    return message


def _previous_legend(reports: list[UsageReport], timezone_label: str) -> str | None:
    """One-line explanation of the ``was X%`` clause, dated from the previous run."""
    stamps = [report.fetched_at for report in reports if report.fetched_at]
    if not stamps:
        return None
    stamp = max(stamps).astimezone(KST)
    return (
        f"_was X% from the previous report ({stamp:%m-%d %H:%M} {timezone_label}); "
        "omitted when unavailable or the window rolled over_"
    )
