"""A plain SHA-256 helper.

Used two ways: the *vulnerable* app stores and compares client-computed password digests
(the credential sink), and the fixtures derive those digests from the demo passwords. This is
an ordinary hash — nothing here is a key-derivation function; that is exactly the lesson.
"""

from __future__ import annotations

import hashlib


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
