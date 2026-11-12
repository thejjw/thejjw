"""Offline tests for the usage contract and renderer.

Run from the ``py`` directory: ``python3 -m unittest discover -s aiusage/tests -t .``
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aiusage.contract import RESET_API, RESET_DERIVED, RESET_RELATIVE, UsageReport, Window, parse_timestamp
from aiusage.render import format_countdown, format_percent, format_reset, render_message

FIXTURES = Path(__file__).parent / "fixtures"
# The report time used by every assertion: 08:00 KST on 11-12.
NOW = datetime(2026, 11, 11, 23, 0, tzinfo=timezone.utc)


def load_hermes(provider: str) -> UsageReport:
    """Build a report from a captured ``hermes usage --json`` document."""
    doc = json.loads((FIXTURES / f"hermes-{provider}.json").read_text())
    return UsageReport.from_document(doc)


def hermes_reports() -> list[UsageReport]:
    """The three providers owned by the Hermes CLI."""
    return [load_hermes(name) for name in ("openai-codex", "anthropic", "opencode-go")]


class FormatTests(unittest.TestCase):
    def test_percent_keeps_sub_one_detail_and_drops_noise(self):
        self.assertEqual(format_percent(0.0), "0%")
        self.assertEqual(format_percent(2.0), "2%")
        self.assertEqual(format_percent(0.06), "0.06%")
        self.assertEqual(format_percent(42.4), "42%")
        self.assertIsNone(format_percent(None))

    def test_countdown_buckets(self):
        self.assertEqual(format_countdown(timedelta(days=6, hours=1)), "in 6d 1h")
        self.assertEqual(format_countdown(timedelta(hours=5, minutes=12)), "in 5h 12m")
        self.assertEqual(format_countdown(timedelta(hours=5)), "in 5h")
        self.assertEqual(format_countdown(timedelta(minutes=13)), "in 13m")
        self.assertEqual(format_countdown(timedelta(seconds=-5)), "passed")


class ResetTests(unittest.TestCase):
    def test_reported_reset_renders_in_kst_with_countdown(self):
        window = Window("Weekly", 42.0, parse_timestamp("2026-11-17T00:00:00Z"), RESET_API)
        self.assertEqual(format_reset(window, NOW), "resets 11-17 09:00 KST (in 5d 1h)")

    def test_derived_and_relative_resets_render_like_reported_ones(self):
        stamped = parse_timestamp("2026-11-12T14:00:00Z")
        for source in (RESET_DERIVED, RESET_RELATIVE):
            window = Window("5h", 12.0, stamped, source)
            self.assertEqual(format_reset(window, NOW), "resets 11-12 23:00 KST (in 15h)")

    def test_missing_reset_is_stated_not_omitted(self):
        rolling = Window("5h tokens", 12.0, None, None, reset_note="5h rolling window")
        self.assertEqual(format_reset(rolling, NOW), "reset not reported (5h rolling window)")
        bare = Window("Weekly", 3.0, None, None)
        self.assertEqual(format_reset(bare, NOW), "reset n/a")

    def test_reset_in_the_past_says_passed(self):
        window = Window("Session", 8.0, parse_timestamp("2026-11-11T20:00:00Z"), RESET_API)
        self.assertEqual(format_reset(window, NOW), "resets 11-12 05:00 KST (passed)")


class ContractTests(unittest.TestCase):
    def test_hermes_fixture_round_trips(self):
        for report in hermes_reports():
            restored = UsageReport.from_document(report.to_document())
            self.assertEqual(restored.provider, report.provider)
            self.assertEqual([w.label for w in restored.windows], [w.label for w in report.windows])
            self.assertEqual(restored.plan, report.plan)
            self.assertEqual(restored.details, report.details)

    def test_epoch_milliseconds_and_seconds_both_parse(self):
        self.assertEqual(parse_timestamp(1795599764998), parse_timestamp(1795599764.998))

    def test_naive_and_bad_timestamps_do_not_raise(self):
        self.assertIsNotNone(parse_timestamp("2026-11-11T09:00:00"))
        self.assertIsNone(parse_timestamp("not a date"))

    def test_report_without_windows_but_with_note_is_available(self):
        report = UsageReport(
            provider="deepseek",
            source="balance_api",
            fetched_at=NOW,
            details=["CNY 599.52 · USD 0.00"],
            note="prepaid account, no reset window",
        )
        self.assertTrue(report.available)


class MessageTests(unittest.TestCase):
    def test_golden_message_from_captured_hermes_fixtures(self):
        expected = (
            "AI usage — 11-12 08:00 KST\n"
            "\n"
            "Codex · Prolite\n"
            "  Weekly · 3% used · resets 11-12 15:35 KST (in 7h 35m)\n"
            "  You have 2 resets banked - use /usage reset to activate\n"
            "\n"
            "Anthropic\n"
            "  Current session · 0% used · resets 11-11 19:20 KST (passed)\n"
            "  Current week · 2% used · resets 11-17 06:00 KST (in 4d 22h)\n"
            "\n"
            "OpenCodeGo\n"
            "  Rolling window · 0% used · resets 11-11 21:26 KST (passed)\n"
            "  Weekly · 0% used · resets 11-16 09:00 KST (in 4d 1h)\n"
            "  Monthly · 1% used · resets 12-01 20:13 KST (in 19d 12h)"
        )
        self.assertEqual(render_message(hermes_reports(), NOW), expected)

    def test_unavailable_providers_are_footered_not_dropped_silently(self):
        reports = hermes_reports() + [UsageReport.unavailable("zai", "401 invalid key")]
        message = render_message(reports, NOW)
        self.assertIn("1 unavailable: Z.AI (401 invalid key)", message)
        self.assertNotIn("Z.AI\n", message)

    def test_unknown_provider_sorts_after_known_ones(self):
        reports = [
            UsageReport("aaa-new", "x", NOW, windows=[Window("Weekly", 1.0)]),
            UsageReport("kimi", "y", NOW, windows=[Window("Weekly", 2.0)]),
        ]
        message = render_message(reports, NOW)
        self.assertLess(message.index("Kimi"), message.index("aaa-new"))

    def test_empty_report_list_still_produces_a_message(self):
        self.assertIn("No provider reported usage.", render_message([], NOW))


if __name__ == "__main__":
    unittest.main()
