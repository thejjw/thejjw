"""Offline parser tests against captured provider payloads.

Run from the ``py`` directory: ``python3 -m unittest discover -s aiusage/tests -t .``
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aiusage.providers import deepseek, kimi, minimax, zai

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 11, 23, 0, tzinfo=timezone.utc)


def fixture(name: str) -> dict:
    """Load one captured response."""
    return json.loads((FIXTURES / name).read_text())


class ZaiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = zai.parse(
            fixture("zai_quota-limit.json"),
            fixture("zai_model-usage.json"),
            fixture("zai_tool-usage.json"),
            fetched_at=NOW,
        )

    def test_labels_and_percentages(self):
        self.assertEqual([w.label for w in self.report.windows], ["monthly tools", "5h tokens"])
        self.assertEqual([w.used_percent for w in self.report.windows], [0.0, 0.0])
        self.assertEqual(self.report.plan, "max")

    def test_reported_reset_is_kept_and_rolling_window_is_flagged(self):
        monthly, five_hour = self.report.windows
        self.assertIsNotNone(monthly.resets_at)
        self.assertEqual(monthly.resets_source, "api")
        self.assertIsNone(five_hour.resets_at)
        self.assertEqual(five_hour.reset_note, "5h rolling")

    def test_activity_lines_come_from_the_monitor_endpoints(self):
        self.assertEqual(self.report.details[0], "24h: 57 calls · 5.79M tokens (GLM-5.3-Flash 5.79M)")
        self.assertEqual(self.report.details[1], "24h tools: none")

    def test_failed_envelope_raises_instead_of_rendering_zeros(self):
        with self.assertRaises(RuntimeError):
            zai.parse({"code": 1001, "success": False, "msg": "invalid api key"})


class KimiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = kimi.parse(fixture("kimi_usages.json"), fetched_at=NOW)

    def test_both_windows_use_the_ratio_view(self):
        self.assertEqual([w.label for w in self.report.windows], ["5h", "weekly"])
        self.assertEqual(self.report.windows[0].used_percent, 0.0)
        self.assertAlmostEqual(self.report.windows[1].used_percent or 0, 0.06, places=6)

    def test_resets_are_absolute_and_marked_api(self):
        for window in self.report.windows:
            self.assertIsNotNone(window.resets_at)
            self.assertEqual(window.resets_source, "api")


class MinimaxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = minimax.parse(fixture("minimax_token_plan.json"), fetched_at=NOW)

    def test_one_interval_and_one_week_per_model(self):
        self.assertEqual(
            [w.label for w in self.report.windows],
            ["general interval", "general week", "video interval", "video week"],
        )

    def test_remaining_percent_is_inverted(self):
        general_interval, general_week = self.report.windows[:2]
        self.assertEqual(general_interval.used_percent, 0.0)
        self.assertEqual(general_week.used_percent, 1.0)

    def test_counts_only_shown_when_a_total_exists(self):
        self.assertIsNone(self.report.windows[0].detail)
        self.assertEqual(self.report.windows[2].detail, "0/3")


class DeepseekTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = deepseek.parse(fixture("deepseek_balance.json"), fetched_at=NOW)

    def test_balances_render_as_details_without_windows(self):
        self.assertEqual(self.report.windows, [])
        self.assertEqual(self.report.details, ["CNY 599.52", "USD 0.00"])
        self.assertIn("prepaid", self.report.note or "")
        self.assertTrue(self.report.available)


if __name__ == "__main__":
    unittest.main()
