"""Z.AI (Zhipu GLM Coding Plan) usage: quota limits plus 24h model/tool activity.

Auth note: this API accepts the bare key in ``Authorization`` (no ``Bearer``
prefix), which is what the upstream PowerShell function sends. Failures arrive
as HTTP 200 with ``success: false``, so the envelope must be checked explicitly
-- otherwise a bad key renders as an all-zero table.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..contract import RESET_API, UsageReport, Window, parse_timestamp
from ..http import get_json, quote_window
from ..render import format_tokens

BASE = "https://api.z.ai/api/monitor/usage"
SOURCE = "monitor_api"

# Window code -> label fragment. 3 = 5-hour rolling, 5 = monthly, 6 = weekly.
UNIT_LABELS: dict[int, str] = {3: "5h", 5: "monthly", 6: "weekly"}
WINDOW_NOUNS = {"TIME_LIMIT": "tools", "TOKENS_LIMIT": "tokens"}


def _window_name(unit: int | None) -> str:
    """Map a window code to a short label, keeping unknown codes visible."""
    if isinstance(unit, int) and unit in UNIT_LABELS:
        return UNIT_LABELS[unit]
    return f"unit{unit}" if unit is not None else "rolling"


def _unwrap(doc: dict) -> dict:
    """Return the ``data`` payload, raising when the envelope reports a failure."""
    code = doc.get("code")
    if doc.get("success") is False or (code is not None and str(code) not in ("200", "0")):
        raise RuntimeError(f"code {code}: {doc.get('msg') or 'request rejected'}")
    return doc.get("data") or {}


def _limit_label(limit: dict) -> str:
    """Name a limit from its type and window code, e.g. '5h tokens'."""
    noun = WINDOW_NOUNS.get(str(limit.get("type")), "quota")
    return f"{_window_name(limit.get('unit'))} {noun}"


def _as_float(value: float | int | str | None) -> float | None:
    """Coerce numeric strings to float, tolerating junk."""
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


def _sum_series(value: object) -> int:
    """Total a series of hourly counts, tolerating a scalar or junk."""
    if isinstance(value, list):
        return int(sum(float(item) for item in value if isinstance(item, (int, float))))
    if isinstance(value, (int, float, str)):
        return int(float(value or 0))
    return 0


def parse(
    quota: dict,
    model_usage: dict | None = None,
    tool_usage: dict | None = None,
    *,
    fetched_at: datetime | None = None,
) -> UsageReport:
    """Build the report from the quota, model-usage and tool-usage responses."""
    fetched = fetched_at or datetime.now(timezone.utc)
    data = _unwrap(quota)
    windows: list[Window] = []
    for limit in data.get("limits") or []:
        reset_at = parse_timestamp(limit.get("nextResetTime"))
        window_label = _window_name(limit.get("unit"))
        detail = None
        used, total = _as_float(limit.get("currentValue")), _as_float(limit.get("usage"))
        if used is not None and total:
            detail = f"{used:.0f}/{total:.0f}"
        windows.append(
            Window(
                label=_limit_label(limit),
                used_percent=_as_float(limit.get("percentage")),
                resets_at=reset_at,
                resets_source=RESET_API if reset_at else None,
                # A rolling window has no anchor, so an absent reset stays absent.
                reset_note=None if reset_at else f"{window_label} rolling",
                detail=detail,
            )
        )

    details: list[str] = []
    if model_usage:
        total = (_unwrap(model_usage).get("totalUsage") or {})
        calls = total.get("totalModelCallCount")
        tokens = total.get("totalTokensUsage")
        line = f"24h: {int(calls or 0)} calls · {format_tokens(_as_float(tokens))} tokens"
        models = total.get("modelSummaryList") or []
        if models:
            top = max(models, key=lambda m: _as_float(m.get("totalTokens")) or 0)
            line += f" ({top.get('modelName')} {format_tokens(_as_float(top.get('totalTokens')))})"
        details.append(line)
    if tool_usage:
        data_tools = _unwrap(tool_usage)
        counts = {
            "search": _sum_series(data_tools.get("networkSearchCount")),
            "web-reader": _sum_series(data_tools.get("webReadMcpCount")),
            "zread": _sum_series(data_tools.get("zreadMcpCount")),
        }
        used = {name: value for name, value in counts.items() if value}
        if used:
            details.append("24h tools: " + ", ".join(f"{name} {value}" for name, value in used.items()))
        else:
            details.append("24h tools: none")

    return UsageReport(
        provider="zai",
        source=SOURCE,
        fetched_at=fetched,
        plan=str(data.get("level")) if data.get("level") else None,
        windows=windows,
        details=details,
    )


def _window_query(now: datetime) -> str:
    """Build the startTime/endTime query the monitor API expects (yesterday hour -> now hour end)."""
    start = (now - timedelta(days=1)).replace(minute=0, second=0, microsecond=0)
    end = now.replace(minute=59, second=59, microsecond=0)
    return (
        f"?startTime={quote_window(start.strftime('%Y-%m-%d %H:%M:%S'))}"
        f"&endTime={quote_window(end.strftime('%Y-%m-%d %H:%M:%S'))}"
    )


def fetch(api_key: str, *, fetched_at: datetime | None = None) -> UsageReport:
    """Query the three monitor endpoints; quota is mandatory, activity is best effort."""
    now = datetime.now(timezone.utc)
    headers = {"Authorization": api_key, "Accept": "application/json"}
    query = _window_query(now)

    quota = get_json(f"{BASE}/quota/limit", headers)
    model_usage = None
    tool_usage = None
    for name, target in (("model-usage", "model"), ("tool-usage", "tool")):
        try:
            result = get_json(f"{BASE}/{name}{query}", headers)
            # An HTTP-200 failure envelope passes get_json but raises later in
            # parse(), outside any best-effort boundary, and would erase the
            # quota already fetched. Validate it here; keep the original
            # envelope because parse() unwraps optional payloads itself.
            _unwrap(result)
        except Exception:
            result = None
        if target == "model":
            model_usage = result
        else:
            tool_usage = result
    return parse(quota, model_usage, tool_usage, fetched_at=fetched_at)
