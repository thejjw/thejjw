"""Offline tests for the digest's previous-run ``was X%`` context.

Run from the ``hermes`` directory:
``python3 -m unittest discover -s aiusage/tests -t .``
"""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aiusage.cli import load_documents
from aiusage.contract import UsageReport, Window
from aiusage.render import build_previous_lookup, render_message

FIXTURES = Path(__file__).parent / "fixtures"
# 08:00 KST on 11-12, the report time used by every assertion.
NOW = datetime(2026, 11, 11, 23, 0, tzinfo=timezone.utc)


def load(provider: str) -> UsageReport:
    """Build a report from a captured ``hermes usage --json`` document."""
    return UsageReport.from_document(json.loads((FIXTURES / f"hermes-{provider}.json").read_text()))


def with_percent(report: UsageReport, label: str, percent: float) -> UsageReport:
    """Copy a report with one window's used-percent replaced."""
    doc = report.to_document()
    for window in doc["windows"]:
        if window["label"] == label:
            window["used_percent"] = percent
    return UsageReport.from_document(doc)


def without_label(report: UsageReport, label: str) -> UsageReport:
    """Copy a report with one window removed."""
    doc = report.to_document()
    doc["windows"] = [w for w in doc["windows"] if w["label"] != label]
    return UsageReport.from_document(doc)


def with_reset(report: UsageReport, label: str, resets_at: str) -> UsageReport:
    """Copy a report with one window's reset time replaced."""
    doc = report.to_document()
    for window in doc["windows"]:
        if window["label"] == label:
            window["resets_at"] = resets_at
    return UsageReport.from_document(doc)


class PreviousContextTests(unittest.TestCase):
    def test_same_period_window_carries_was_clause(self):
        current = with_percent(load("anthropic"), "Current week", 5.0)
        previous = with_percent(load("anthropic"), "Current week", 2.0)
        message = render_message([current], NOW, previous=[previous])
        self.assertIn("Current week · 5% used (was 2%)", message)

    def test_unchanged_value_is_still_shown(self):
        current = with_percent(load("anthropic"), "Current week", 2.0)
        previous = with_percent(load("anthropic"), "Current week", 2.0)
        message = render_message([current], NOW, previous=[previous])
        self.assertIn("Current week · 2% used (was 2%)", message)

    def test_rolled_window_omits_was_clause(self):
        current = with_percent(load("anthropic"), "Current week", 5.0)
        previous = with_reset(
            with_percent(load("anthropic"), "Current week", 2.0),
            "Current week",
            "2026-11-10T21:00:00+00:00",
        )
        message = render_message([current], NOW, previous=[previous])
        self.assertIn("Current week · 5% used · resets", message)
        self.assertNotIn("Current week · 5% used (was", message)

    def test_new_window_label_omits_was_clause(self):
        previous = without_label(load("anthropic"), "Current week")
        message = render_message([load("anthropic")], NOW, previous=[previous])
        self.assertIn("Current week · 2% used · resets", message)
        self.assertNotIn("Current week · 2% used (was", message)

    def test_unavailable_previous_omits_was_clause(self):
        previous = UsageReport.unavailable("anthropic", "no data")
        message = render_message([load("anthropic")], NOW, previous=[previous])
        self.assertNotIn("(was", message)

    def test_legend_dates_the_previous_run(self):
        message = render_message([load("anthropic")], NOW, previous=[load("anthropic")])
        # The fixture was fetched 2026-11-11T09:22:09Z, which is 18:22 KST.
        self.assertIn("_was X% from the previous report (11-11 18:22 KST)", message)

    def test_no_legend_without_previous(self):
        message = render_message([load("anthropic")], NOW)
        self.assertNotIn("was X%", message)

    def test_lookup_skips_windows_without_reset_or_percent(self):
        report = UsageReport(
            provider="probe",
            source="test",
            fetched_at=NOW,
            windows=[
                Window(label="no-reset", used_percent=1.0, resets_at=None),
                Window(label="no-percent", used_percent=None, resets_at=NOW),
                Window(label="usable", used_percent=3.0, resets_at=NOW),
            ],
        )
        self.assertEqual(list(build_previous_lookup([report])), [("probe", "usable", NOW)])


class SnapshotTests(unittest.TestCase):
    def test_load_documents_reads_a_snapshot_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "previous.json"
            path.write_text(json.dumps([load("anthropic").to_document()]))
            reports = load_documents([str(path)])
        self.assertEqual([report.provider for report in reports], ["anthropic"])


if __name__ == "__main__":
    unittest.main()
