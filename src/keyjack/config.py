"""Runtime configuration, read once from the environment.

The secure application is the only application mode in this baseline. Later contrast
variants add their own gated entry points; this module keeps the mode explicit so a
vulnerable surface can never be the default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

SECURE_MODE = "secure"


@dataclass(frozen=True)
class Settings:
    """Immutable process settings."""

    mode: str = SECURE_MODE
    db_url: str = "sqlite+pysqlite:////data/keyjack.db"
    reseed_on_startup: bool = True
    session_ttl_seconds: int = 3600
    pickup_ttl_seconds: int = 3600
    # Argon2id parameters kept modest so credential verification never pushes the
    # demonstration past its five-minute budget while remaining a real KDF.
    argon2_time_cost: int = 2
    argon2_memory_cost_kib: int = 64 * 1024
    argon2_parallelism: int = 2


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_settings() -> Settings:
    """Build :class:`Settings` from the environment with safe defaults."""

    defaults = Settings()
    return Settings(
        mode=os.environ.get("KEYJACK_MODE", defaults.mode),
        db_url=os.environ.get("KEYJACK_DB_URL", defaults.db_url),
        reseed_on_startup=_flag("KEYJACK_RESEED", defaults.reseed_on_startup),
        session_ttl_seconds=int(
            os.environ.get("KEYJACK_SESSION_TTL", defaults.session_ttl_seconds)
        ),
        pickup_ttl_seconds=int(
            os.environ.get("KEYJACK_PICKUP_TTL", defaults.pickup_ttl_seconds)
        ),
    )
