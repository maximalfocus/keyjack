"""The client-hashed credential sink: the digest is the credential, so a captured digest wins."""

from __future__ import annotations

import httpx

from keyjack.attacker.cli import replay_digest_attack
from keyjack.fixtures import CAPTURED_SUPERVISOR_DIGEST


def test_captured_digest_replay_approves_attackers_own_order(vuln_base_url: str) -> None:
    result = replay_digest_attack(vuln_base_url)
    # The checked-in supervisor digest authenticated; the attacker approved their own order.
    assert result.extracted_value == CAPTURED_SUPERVISOR_DIGEST
    assert result.response_status == 200
    assert result.order_state == "approved"


def test_secure_login_treats_the_captured_digest_as_a_wrong_password(api: httpx.Client) -> None:
    # Against the secure app the digest is just a wrong password against the KDF.
    res = api.post(
        "/api/login",
        json={"account_id": "sup-navarro", "password": CAPTURED_SUPERVISOR_DIGEST},
    )
    assert res.status_code == 401
    assert res.json() == {"detail": "unauthorized"}
