"""Pure-logic unit tests: authorization, routing, and server-side security primitives."""

from __future__ import annotations

import pytest

from keyjack.config import Settings
from keyjack.domain import compute_authorization, route_state
from keyjack.models import OrderState
from keyjack.security import (
    build_hasher,
    hash_password,
    new_pickup_code,
    new_session_token,
    verify_password,
)

# Fast KDF parameters for unit tests.
FAST = Settings(argon2_time_cost=1, argon2_memory_cost_kib=8 * 1024, argon2_parallelism=1)

LIMIT = 25_000


@pytest.mark.parametrize(
    ("restricted", "line_total", "within", "requires"),
    [
        (False, 3_800, True, False),  # under-limit unrestricted -> auto
        (False, 42_000, False, True),  # over-limit unrestricted -> pending
        (True, 22_000, True, True),  # under-limit restricted -> pending
        (True, 189_000, False, True),  # over-limit restricted -> pending
    ],
)
def test_authorization_truth_table(
    restricted: bool, line_total: int, within: bool, requires: bool
) -> None:
    auth = compute_authorization(
        approval_limit_cents=LIMIT, restricted=restricted, line_total_cents=line_total
    )
    assert auth.within_limit is within
    assert auth.requires_supervisor is requires


def test_route_state_maps_verdict() -> None:
    auto = compute_authorization(approval_limit_cents=LIMIT, restricted=False, line_total_cents=100)
    pending = compute_authorization(
        approval_limit_cents=LIMIT, restricted=True, line_total_cents=100
    )
    assert route_state(auto) is OrderState.AUTO_APPROVED
    assert route_state(pending) is OrderState.PENDING_SUPERVISOR


def test_kdf_roundtrip_and_reject() -> None:
    hasher = build_hasher(FAST)
    stored = hash_password(hasher, "correct horse")
    assert verify_password(hasher, stored, "correct horse") is True
    assert verify_password(hasher, stored, "wrong password") is False


def test_kdf_output_is_not_the_password() -> None:
    hasher = build_hasher(FAST)
    stored = hash_password(hasher, "s3cret-demo")
    assert stored.startswith("$argon2id$")
    assert "s3cret-demo" not in stored


def test_kdf_verify_tolerates_garbage_hash() -> None:
    hasher = build_hasher(FAST)
    # A malformed stored hash is a failed verification, never an exception.
    assert verify_password(hasher, "not-a-hash", "whatever") is False


def test_pickup_code_is_high_entropy_and_unique() -> None:
    a, b = new_pickup_code(), new_pickup_code()
    assert a.startswith("NB-")
    assert a != b
    # token_urlsafe(32) -> 32 random bytes -> >=43 chars after the prefix.
    assert len(a) - len("NB-") >= 43


def test_session_tokens_unique() -> None:
    assert new_session_token() != new_session_token()


def test_signature_round_trip_and_tamper() -> None:
    from keyjack.signing import canonical_order_string, sign, verify

    message = canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1001",
        unit_price_cents=1, restricted=False, line_total_cents=1,
    )
    sig = sign("a-key", message)
    assert verify("a-key", message, sig) is True
    assert verify("a-key", message, "00" * 32) is False
    tampered = canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1001",
        unit_price_cents=189_000, restricted=True, line_total_cents=189_000,
    )
    assert verify("a-key", tampered, sig) is False
