"""AI subscription usage collection and rendering.

``aiusage`` fetches the providers Hermes does not cover (Z.AI, Kimi, MiniMax,
DeepSeek) and renders them together with the ones ``hermes usage`` already
reports, as one plain-text message suitable for ``hermes send``.
"""

from .contract import RESET_API, RESET_DERIVED, RESET_RELATIVE, UsageReport, Window, parse_timestamp
from .render import render_message, render_report, render_window

__all__ = [
    "RESET_API",
    "RESET_DERIVED",
    "RESET_RELATIVE",
    "UsageReport",
    "Window",
    "parse_timestamp",
    "render_message",
    "render_report",
    "render_window",
]
