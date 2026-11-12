"""Offline credential-resolution tests; no test reads the real user's files.

Run from the ``hermes`` directory: ``python -B -m unittest discover -s aiusage/tests``
"""

from __future__ import annotations

import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiusage import keys


class HermesHomeDefaultTests(unittest.TestCase):
    """The import-time HERMES_HOME default follows the invoking user's home."""

    def tearDown(self) -> None:
        # Reload with the real environment so later tests never see a patched home.
        importlib.reload(keys)

    def reload_default(self, env: dict[str, str], home: str) -> Path:
        """Re-import keys with os.environ and Path.home() pinned."""
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(Path, "home", return_value=Path(home)):
                importlib.reload(keys)
        return keys.HERMES_HOME

    def test_unset_hermes_home_resolves_to_the_user_home(self):
        self.assertEqual(self.reload_default({}, "/home/alice"), Path("/home/alice/.hermes"))

    def test_empty_hermes_home_is_treated_as_unset(self):
        # An empty value must not fall back to the current directory.
        self.assertEqual(
            self.reload_default({"HERMES_HOME": ""}, "/home/alice"), Path("/home/alice/.hermes")
        )

    def test_configured_hermes_home_wins_over_the_default_home(self):
        self.assertEqual(
            self.reload_default({"HERMES_HOME": "/data/hermes"}, "/home/alice"),
            Path("/data/hermes"),
        )

    def test_root_home_still_resolves_to_root_hermes(self):
        self.assertEqual(self.reload_default({}, "/root"), Path("/root/.hermes"))


class ResolveTests(unittest.TestCase):
    """Precedence: explicit key, process environment, ``.env``, credential pool."""

    def make_home(self, files: dict[str, str]) -> Path:
        """Build a disposable ``.hermes`` home containing the given files."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    def test_dotenv_key_is_resolved_from_the_synthetic_home(self):
        home = self.make_home({".env": "ZAI_API_KEY=dotenv-key\n"})

        self.assertEqual(keys.resolve("zai", environ={}, hermes_home=home), "dotenv-key")

    def test_pool_key_is_resolved_from_auth_json(self):
        pool = {"credential_pool": {"zai": [{"access_token": "pool-key"}]}}
        home = self.make_home({"auth.json": json.dumps(pool)})

        self.assertEqual(keys.resolve("zai", environ={}, hermes_home=home), "pool-key")

    def test_explicit_key_wins_over_every_other_source(self):
        pool = {"credential_pool": {"zai": [{"access_token": "pool-key"}]}}
        home = self.make_home({".env": "ZAI_API_KEY=dotenv-key\n", "auth.json": json.dumps(pool)})

        resolved = keys.resolve("zai", "explicit-key", environ={"ZAI_API_KEY": "env-key"}, hermes_home=home)

        self.assertEqual(resolved, "explicit-key")

    def test_environment_key_wins_over_files(self):
        home = self.make_home({".env": "ZAI_API_KEY=dotenv-key\n"})

        self.assertEqual(
            keys.resolve("zai", environ={"ZAI_API_KEY": "env-key"}, hermes_home=home), "env-key"
        )

    def test_missing_files_return_no_credential_without_crashing(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.assertIsNone(keys.resolve("zai", environ={}, hermes_home=Path(tmp.name)))
        self.assertIsNone(keys.resolve("zai", environ={}, hermes_home=Path(tmp.name) / "missing"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
