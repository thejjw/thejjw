"""Minimal HTTP JSON client: timeout, bounded retries, short error messages.

No third-party dependencies, so the collected data can be produced by the
system interpreter without a virtualenv.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 2


class ProviderError(RuntimeError):
    """Short, user-facing failure reason for one provider."""


def get_json(
    url: str,
    headers: dict[str, str] | None = None,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> dict:
    """GET a URL and decode JSON, retrying only on transient failures."""
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            # 4xx is an auth/shape problem: retrying cannot help.
            if exc.code < 500:
                raise ProviderError(f"HTTP {exc.code}") from exc
            last_error = ProviderError(f"HTTP {exc.code}")
        except urllib.error.URLError as exc:
            last_error = ProviderError(f"network: {exc.reason}")
        except (TimeoutError, json.JSONDecodeError) as exc:
            last_error = ProviderError(f"{type(exc).__name__}")
        if attempt < retries:
            time.sleep(1.5 * (attempt + 1))
    raise last_error or ProviderError("request failed")


def quote_window(value: str) -> str:
    """Percent-encode a timestamp for a query string (' ' becomes %20, not '+')."""
    return urllib.parse.quote(value, safe="")
