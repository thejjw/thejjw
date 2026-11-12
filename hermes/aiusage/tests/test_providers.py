"""Offline parser tests against captured provider payloads.

Run from the ``py`` directory: ``python3 -m unittest discover -s aiusage/tests -t .``
"""

from __future__ import annotations

import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from aiusage.cli import collect
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


class ZaiFetchTests(unittest.TestCase):
    """fetch() must keep a valid quota when optional activity is unavailable."""

    QUOTA = fixture("zai_quota-limit.json")
    MODEL = fixture("zai_model-usage.json")
    TOOL = fixture("zai_tool-usage.json")

    def fetch_with(self, responses: list) -> zai.UsageReport:
        """Run zai.fetch with get_json returning the given objects in call order."""
        with mock.patch.object(zai, "get_json", side_effect=responses):
            return zai.fetch("test-key", fetched_at=NOW)

    def test_rejected_model_envelope_keeps_quota(self):
        report = self.fetch_with(
            [self.QUOTA, {"code": 429, "success": False, "msg": "rate limited"}, self.TOOL]
        )

        self.assertTrue(report.windows)
        self.assertEqual(report.details, ["24h tools: none"])

    def test_rejected_tool_envelope_keeps_quota_and_model_activity(self):
        report = self.fetch_with(
            [self.QUOTA, self.MODEL, {"code": 429, "success": False, "msg": "rate limited"}]
        )

        self.assertTrue(report.windows)
        self.assertEqual(report.details, ["24h: 57 calls · 5.79M tokens (GLM-5.3-Flash 5.79M)"])

    def test_both_optional_failures_keep_quota(self):
        report = self.fetch_with(
            [self.QUOTA, {"code": 429, "success": False}, {"code": 429, "success": False}]
        )

        self.assertTrue(report.windows)
        self.assertEqual(report.details, [])

    def test_transport_failures_stay_best_effort(self):
        report = self.fetch_with([self.QUOTA, ConnectionError("boom"), self.TOOL])

        self.assertTrue(report.windows)
        self.assertEqual(report.details, ["24h tools: none"])

    def test_rejected_quota_still_fails_the_provider(self):
        with mock.patch.object(
            zai, "get_json", return_value={"code": 1001, "success": False, "msg": "invalid api key"}
        ):
            with self.assertRaises(RuntimeError):
                zai.fetch("test-key", fetched_at=NOW)

    def test_all_successful_output_matches_parse(self):
        report = self.fetch_with([self.QUOTA, self.MODEL, self.TOOL])

        expected = zai.parse(self.QUOTA, self.MODEL, self.TOOL, fetched_at=NOW)
        self.assertEqual(report, expected)

    def test_collection_keeps_zai_available_when_optional_activity_fails(self):
        responses = [self.QUOTA, {"code": 429, "success": False, "msg": "rate limited"}, self.TOOL]
        with mock.patch.object(zai, "get_json", side_effect=responses):
            reports = collect(["zai"], explicit={"zai": "test-key"})

        self.assertIsNone(reports[0].unavailable_reason)
        self.assertTrue(reports[0].available)
        self.assertTrue(reports[0].windows)


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

    def test_modern_five_hour_keeps_legacy_weekly(self):
        # Dropping only usages.limit_7d must not lose the weekly quota: the
        # legacy top-level usage fills the gap, and the 300-minute legacy
        # limits entry must not duplicate the modern 5h row.
        doc = copy.deepcopy(fixture("kimi_usages.json"))
        del doc["usages"]["limit_7d"]
        doc["usage"]["remaining"] = "50"  # distinct value proving the legacy source filled the gap

        report = kimi.parse(doc, fetched_at=NOW)

        self.assertEqual([w.label for w in report.windows], ["5h", "weekly"])
        self.assertEqual(report.windows[1].used_percent, 50.0)
        self.assertEqual(report.windows[1].resets_source, "api")
        self.assertEqual(
            report.windows[1].resets_at,
            datetime(2026, 11, 13, 0, 32, 9, 619778, tzinfo=timezone.utc),
        )

    def test_modern_weekly_keeps_legacy_five_hour(self):
        # The reverse mixed response: legacy 5h survives next to modern weekly.
        doc = copy.deepcopy(fixture("kimi_usages.json"))
        del doc["usages"]["limit_5h"]
        doc["limits"][0]["detail"]["remaining"] = "40"

        report = kimi.parse(doc, fetched_at=NOW)

        self.assertEqual([w.label for w in report.windows], ["weekly", "5h"])
        self.assertAlmostEqual(report.windows[0].used_percent or 0, 0.06, places=6)
        self.assertEqual(report.windows[1].used_percent, 60.0)
        self.assertEqual(
            report.windows[1].resets_at,
            datetime(2026, 11, 11, 12, 32, 9, 619778, tzinfo=timezone.utc),
        )

    def test_legacy_only_payload_keeps_windows_and_reset_data(self):
        doc = copy.deepcopy(fixture("kimi_usages.json"))
        del doc["usages"]

        report = kimi.parse(doc, fetched_at=NOW)

        self.assertEqual([w.label for w in report.windows], ["weekly", "5h"])
        self.assertEqual(report.windows[0].used_percent, 0.0)
        for window in report.windows:
            self.assertIsNotNone(window.resets_at)
            self.assertEqual(window.resets_source, "api")

    def test_empty_modern_block_zero_usage_and_extra_durations_fill_in(self):
        # An empty modern block must not suppress legacy fallback; numeric zero
        # is valid usage; a duplicate legacy identity is dropped once; entries
        # without window metadata are always kept (no safe identity to match).
        doc = {
            "usage": {"limit": "100", "remaining": "100", "resetTime": "2026-11-13T00:00:00Z"},
            "limits": [
                {
                    "window": {"duration": 30, "timeUnit": "TIME_UNIT_MINUTE"},
                    "detail": {"limit": "10", "remaining": "0"},
                },
                {
                    "window": {"duration": 30, "timeUnit": "TIME_UNIT_MINUTE"},
                    "detail": {"limit": "10", "remaining": "0"},
                },
                {"detail": {"limit": "5", "remaining": "1"}},
            ],
            "usages": {},
        }

        report = kimi.parse(doc, fetched_at=NOW)

        self.assertEqual([w.label for w in report.windows], ["weekly", "30m", "quota"])
        self.assertEqual(report.windows[0].used_percent, 0.0)
        self.assertEqual(report.windows[1].used_percent, 100.0)
        self.assertIsNone(report.windows[1].resets_at)
        self.assertIsNone(report.windows[1].resets_source)

    def test_relative_reset_is_computed_from_the_pinned_fetch_time(self):
        doc = copy.deepcopy(fixture("kimi_usages.json"))
        del doc["usages"]["limit_7d"]
        doc["limits"] = [
            {
                "window": {"duration": 30, "timeUnit": "TIME_UNIT_MINUTE"},
                "detail": {"limit": "10", "remaining": "9", "ttl": 600},
            }
        ]

        report = kimi.parse(doc, fetched_at=NOW)

        self.assertEqual([w.label for w in report.windows], ["5h", "weekly", "30m"])
        self.assertEqual(report.windows[2].resets_at, datetime(2026, 11, 11, 23, 10, tzinfo=timezone.utc))
        self.assertEqual(report.windows[2].resets_source, "relative")

    def test_malformed_legacy_numbers_keep_the_window_without_a_percent(self):
        # Junk numerics are not silently converted to zero: the window is
        # reported, the percentage stays unknown.
        doc = copy.deepcopy(fixture("kimi_usages.json"))
        del doc["usages"]
        doc["usage"]["limit"] = "abc"

        report = kimi.parse(doc, fetched_at=NOW)

        self.assertEqual(len(report.windows), 2)
        self.assertIsNone(report.windows[0].used_percent)


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
