"""A single UTC clock helper.

All stored timestamps are naive UTC. Keeping one source avoids mixing naive and aware
datetimes, which would otherwise break expiry comparisons under SQLite.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)
