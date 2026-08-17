"""A single UTC clock helper.

All stored timestamps are naive UTC. Keeping one source avoids mixing naive and aware
datetimes, which would otherwise break expiry comparisons under SQLite.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def from_epoch(epoch: int) -> datetime:
    """Naive UTC datetime for a Unix epoch second (used by the weak client-minted code)."""

    return datetime.fromtimestamp(epoch, tz=UTC).replace(tzinfo=None)
