"""Offline tests for the reset-alert selection and rendering.

Run from the ``hermes`` directory:
``python3 -m unittest discover -s aiusage/tests -t .``
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aiusage.alert import due_windows, render_alert
from aiusage.contract import UsageReport
from aiusage.providers.kimi import parse as parse_kimi
from aiusage.providers.minimax import parse as parse_minimax

FIXTURES = Path(__file__).parent / "fixtures"
FETCHED = datetime(2026, 11, 11, 9, 22, tzinfo=timezone.utc)


def _report(provider: str) -> UsageReport:
    """Build a report from a captured document, raw payload for local providers."""
    path = FIXTURES / f"hermes-{provider}.json"
    if path.exists():
        return UsageReport.from_document(json.loads(path.read_text()))
    parser = {"kimi": parse_kimi, "minimax": parse_minimax}[provider]
    name = {"kimi": "kimi_usages.json", "minimax": "minimax_token_plan.json"}[provider]
    return parser(json.loads((FIXTURES / name).read_text()), fetched_at=FETCHED)


def _reports() -> list[UsageReport]:
    """The four weekly plans the alert watches."""
    return [_report(name) for name in ("anthropic", "opencode-go", "kimi", "minimax")]


def _now(day: int) -> datetime:
    """09:00 KST on the given November day."""
    return datetime(2026, 11, day, 0, 0, tzinfo=timezone.utc)


class SelectionTests(unittest.TestCase):
    def test_picks_one_and_two_day_windows_and_drops_the_rest(self):
        entries = due_windows(_reports(), now=_now(15))
        # anthropic resets 11-17 (2 days); opencode-go and minimax 11-16 (1 day);
        # kimi reset 11-13 has already passed.
        self.assertEqual(
            [(days, report.provider) for days, report, _ in entries],
            [(2, "anthropic"), (1, "opencode-go"), (1, "minimax")],
        )

    def test_dedupes_windows_sharing_a_reset_time(self):
        entries = due_windows(_reports(), now=_now(15))
        minimax = [window for _, report, window in entries if report.provider == "minimax"]
        # MiniMax reports general and video weeks resetting together; one line wins.
        self.assertEqual(len(minimax), 1)
        self.assertEqual(minimax[0].label, "general week")

    def test_nothing_due_far_from_any_reset(self):
        self.assertEqual(due_windows(_reports(), now=_now(10)), [])
        self.assertEqual(render_alert(_reports(), now=_now(10)), "")

    def test_within_overrides_the_default_window(self):
        entries = due_windows(_reports(), now=_now(15), within=(2,))
        self.assertEqual([report.provider for _, report, _ in entries], ["anthropic"])

    def test_unavailable_report_is_skipped(self):
        reports = _reports() + [UsageReport.unavailable("kimi", "no credential configured")]
        entries = due_windows(reports, now=_now(15))
        self.assertNotIn("kimi", [report.provider for _, report, _ in entries])

    def test_unmapped_provider_falls_back_to_week_label(self):
        from datetime import timedelta

        from aiusage.contract import Window

        report = UsageReport(
            provider="zai",
            source="test",
            fetched_at=FETCHED,
            windows=[
                Window(
                    label="Weekly bonus",
                    used_percent=5.0,
                    resets_at=FETCHED + timedelta(days=2),
                )
            ],
        )
        entries = due_windows([report], now=FETCHED)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][2].label, "Weekly bonus")


class RenderTests(unittest.TestCase):
    def test_message_groups_by_day_and_orders_providers(self):
        message = render_alert(_reports(), now=_now(15))
        self.assertEqual(
            message,
            "\n".join([
                "Reset alert — 11-15 09:00 KST",
                "",
                "2 days to reset:",
                "  Anthropic · Current week · 2% used · resets 11-17 06:00 KST",
                "",
                "1 day to reset:",
                "  OpenCodeGo · Weekly · 0% used · resets 11-16 09:00 KST",
                "  MiniMax · general week · 1% used · resets 11-16 09:00 KST",
            ]),
        )

    def test_singular_day_label(self):
        message = render_alert(_reports(), now=_now(14))
        self.assertIn("2 days to reset:", message)
        self.assertNotIn("1 day to reset:", message)


if __name__ == "__main__":
    unittest.main()
