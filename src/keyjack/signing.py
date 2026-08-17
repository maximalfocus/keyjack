"""HMAC request signing for the vulnerable contrast.

The vulnerable server verifies signatures **correctly** — a canonical serialization, a
constant-time comparison, rejection of any tampered body — and is defeated anyway, because
the key is shipped to every browser. Nothing here is broken cryptography; that is the point.

The signing key is a conspicuously fictional demonstration value. It secures nothing: it is
delivered to the client on purpose so the demonstration can read it back out.
"""

from __future__ import annotations

import hashlib
import hmac

# A fictional demonstration key. Deliberately shipped to the browser — never a real secret.
DEMO_SIGNING_KEY = "ninebark-demo-signing-key-DO-NOT-REUSE-0000000000"

SIGNED_FIELDS = (
    "part_number",
    "quantity",
    "work_order_id",
    "unit_price_cents",
    "restricted",
    "line_total_cents",
)


def canonical_order_string(
    *,
    part_number: str,
    quantity: int,
    work_order_id: str,
    unit_price_cents: int,
    restricted: bool,
    line_total_cents: int,
) -> str:
    """A deterministic serialization both the client and server compute identically."""

    return "\n".join(
        [
            f"part_number={part_number}",
            f"quantity={quantity}",
            f"work_order_id={work_order_id}",
            f"unit_price_cents={unit_price_cents}",
            f"restricted={'true' if restricted else 'false'}",
            f"line_total_cents={line_total_cents}",
        ]
    )


def sign(key: str, message: str) -> str:
    """HMAC-SHA256 of ``message`` under ``key``, hex-encoded (matches WebCrypto output)."""

    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify(key: str, message: str, signature: str) -> bool:
    """Constant-time verification of a hex signature over ``message``."""

    expected = sign(key, message)
    return hmac.compare_digest(expected, signature)
