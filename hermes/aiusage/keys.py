"""Credential resolution for the four locally fetched providers.

Order: explicit value, then process environment, then ``~/.hermes/.env``, then
the Hermes credential pool (``auth.json``). Nothing here writes or logs a key.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

HERMES_HOME = Path(os.environ.get("HERMES_HOME", "/root/.hermes"))

# Environment variable names each provider's key may arrive under, most specific first.
KEY_ENV_NAMES = {
    "zai": ("ZAI_API_KEY", "GLM_API_KEY"),
    "kimi": ("KIMI_CODE_PLAN_API_KEY", "KIMI_API_KEY"),
    "minimax": ("MINIMAX_API_KEY",),
    "deepseek": ("DEEPSEEK_API_KEY",),
}

# Provider id used inside the Hermes credential pool, where it differs from ours.
POOL_NAME = {
    "zai": "zai",
    "kimi": "kimi-coding",
    "minimax": "minimax",
    "deepseek": "deepseek",
}


def load_dotenv(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE file, ignoring comments and blank lines."""
    values: dict[str, str] = {}
    try:
        text = path.read_text()
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def pool_secret(provider: str, auth_path: Path) -> str | None:
    """Read a provider's api key from the Hermes credential pool, if present."""
    try:
        data = json.loads(auth_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    creds = data.get("credential_pool", {}).get(POOL_NAME.get(provider, provider), [])
    for cred in creds:
        for field in ("access_token", "api_key", "secret"):
            if cred.get(field):
                return str(cred[field])
    return None


def resolve(
    provider: str,
    explicit: str | None = None,
    *,
    environ: dict[str, str] | None = None,
    hermes_home: Path = HERMES_HOME,
) -> str | None:
    """Resolve one provider's api key, or None when no source has it."""
    if explicit:
        return explicit
    env = os.environ if environ is None else environ
    for name in KEY_ENV_NAMES.get(provider, ()):
        if env.get(name):
            return env[name]

    dotenv = load_dotenv(hermes_home / ".env")
    for name in KEY_ENV_NAMES.get(provider, ()):
        if dotenv.get(name):
            return dotenv[name]

    return pool_secret(provider, hermes_home / "auth.json")
