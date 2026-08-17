"""Server-side security primitives for the secure application.

Every security-relevant value the secure application relies on is produced or verified
here, on the server, from state the server holds — never delegated to the browser.
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from .config import Settings


def build_hasher(settings: Settings) -> PasswordHasher:
    """Construct an Argon2id hasher from configured parameters."""

    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost_kib,
        parallelism=settings.argon2_parallelism,
    )


def hash_password(hasher: PasswordHasher, password: str) -> str:
    """Return the Argon2id encoded hash for ``password``. Only this output is stored."""

    return hasher.hash(password)


def verify_password(hasher: PasswordHasher, stored_hash: str, candidate: str) -> bool:
    """Verify a *claimed* password against the stored KDF output.

    A submitted value is always treated as a claim to verify, never as a pre-verified
    proof. Any mismatch, malformed input, or malformed stored hash is a failed
    verification, reported uniformly to the caller with no distinguishing detail.
    """

    try:
        return hasher.verify(stored_hash, candidate)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def new_session_token() -> str:
    """A 256-bit opaque server-issued session token."""

    return secrets.token_urlsafe(32)


def new_pickup_code() -> str:
    """A single-use pickup code with >=256 bits of CSPRNG entropy.

    Formatted with a readable prefix so a human sees it is a server-issued opaque value,
    not a guessable timestamp-derived string.
    """

    return f"NB-{secrets.token_urlsafe(32)}"
