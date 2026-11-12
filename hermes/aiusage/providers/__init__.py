"""Provider adapters, one module per locally fetched service.

Each module exposes ``parse(doc, ...)`` for offline testing and ``fetch(key)``
for the network path.
"""

from . import deepseek, kimi, minimax, zai

# Registry order matches the message order in ``render.PROVIDER_ORDER``.
PROVIDERS = {
    "zai": zai,
    "kimi": kimi,
    "minimax": minimax,
    "deepseek": deepseek,
}

__all__ = ["PROVIDERS", "deepseek", "kimi", "minimax", "zai"]
