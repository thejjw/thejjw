"""Stable data model shared by every usage provider and the renderer.

The document shape mirrors ``hermes usage --json`` so that the four locally
fetched providers and the three Hermes-owned ones can be merged into a single
message. Extra keys are additive only; keep the shared keys stable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# How a window's reset time was obtained. Kept explicit so a computed value is
# never presented as though the provider had reported it.
RESET_API = "api"  # provider returned an absolute timestamp
RESET_DERIVED = "derived"  # computed from a window start plus its duration
RESET_RELATIVE = "relative"  # provider returned a countdown in seconds


def parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 string, epoch seconds, or epoch milliseconds into an aware datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # Epoch milliseconds exceed 1e11; anything smaller is seconds.
        seconds = value / 1000 if abs(value) > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        # Python 3.10's fromisoformat rejects the Z suffix that the APIs emit.
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(slots=True)
class Window:
    """One quota window (a rolling limit, a session, a week, a month)."""

    label: str
    used_percent: float | None = None
    resets_at: datetime | None = None
    resets_source: str | None = None
    reset_note: str | None = None
    detail: str | None = None

    def to_document(self) -> dict:
        """Serialize to the shared JSON shape."""
        return {
            "label": self.label,
            "used_percent": self.used_percent,
            "resets_at": self.resets_at.isoformat() if self.resets_at else None,
            "resets_source": self.resets_source,
            "reset_note": self.reset_note,
            "detail": self.detail,
        }

    @classmethod
    def from_document(cls, doc: dict) -> Window:
        """Rebuild a window from the shared JSON shape."""
        resets_at = parse_timestamp(doc.get("resets_at"))
        source = doc.get("resets_source")
        if resets_at is not None and source is None:
            source = RESET_API
        return cls(
            label=str(doc.get("label") or "window"),
            used_percent=doc.get("used_percent"),
            resets_at=resets_at,
            resets_source=source,
            reset_note=doc.get("reset_note"),
            detail=doc.get("detail"),
        )


@dataclass(slots=True)
class UsageReport:
    """One provider's account limits, or the reason they could not be fetched."""

    provider: str
    source: str
    fetched_at: datetime
    title: str = "Account limits"
    plan: str | None = None
    windows: list[Window] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    note: str | None = None
    unavailable_reason: str | None = None

    @property
    def available(self) -> bool:
        """True when the provider answered and produced something to show."""
        return self.unavailable_reason is None and bool(self.windows or self.details or self.note)

    def to_document(self) -> dict:
        """Serialize to the shared JSON shape (Hermes keys plus additive ones)."""
        return {
            "provider": self.provider,
            "source": self.source,
            "title": self.title,
            "plan": self.plan,
            "fetched_at": self.fetched_at.isoformat(),
            "windows": [window.to_document() for window in self.windows],
            "details": list(self.details),
            "note": self.note,
            "unavailable_reason": self.unavailable_reason,
        }

    @classmethod
    def from_document(cls, doc: dict) -> UsageReport:
        """Rebuild a report from the shared JSON shape."""
        fetched = parse_timestamp(doc.get("fetched_at")) or datetime.now(timezone.utc)
        return cls(
            provider=str(doc.get("provider") or "unknown"),
            source=str(doc.get("source") or "unknown"),
            fetched_at=fetched,
            title=str(doc.get("title") or "Account limits"),
            plan=doc.get("plan"),
            windows=[Window.from_document(w) for w in doc.get("windows") or []],
            details=[str(d) for d in doc.get("details") or []],
            note=doc.get("note"),
            unavailable_reason=doc.get("unavailable_reason"),
        )

    @classmethod
    def unavailable(cls, provider: str, reason: str, source: str = "probe") -> UsageReport:
        """Report carrying only a failure reason, so the footer can name the provider."""
        return cls(
            provider=provider,
            source=source,
            fetched_at=datetime.now(timezone.utc),
            unavailable_reason=reason,
        )
