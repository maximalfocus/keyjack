"""The weak client-generated pickup code: a disclosed timestamp plus three guessable digits."""

from __future__ import annotations

import time

import httpx

from keyjack.attacker.cli import enumerate_pickup_attack
from keyjack.hashing import sha256_hex
from keyjack.signing import DEMO_SIGNING_KEY, canonical_order_string, sign

DEMO_PASSWORDS = {
    "tech-avery": "avery-ninebark-demo",
    "tech-brooks": "brooks-ninebark-demo",
    "sup-navarro": "navarro-ninebark-demo",
}


def _vlogin(client: httpx.Client, account: str) -> None:
    res = client.post(
        "/api/login",
        json={"account_id": account, "password_digest": sha256_hex(DEMO_PASSWORDS[account])},
    )
    assert res.status_code == 200, res.text


def test_enumeration_within_bound_releases_a_peers_restricted_part(vuln_base_url: str) -> None:
    epoch = int(time.time())
    code = f"PU-{epoch}-042"  # a known suffix keeps the test fast; the mechanism is real
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1002",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
        "within_limit": False, "requires_supervisor": True,
        "pickup_code": code, "created_at_epoch": epoch,
    }
    signature = sign(DEMO_SIGNING_KEY, canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1002",
        unit_price_cents=189_000, restricted=True, line_total_cents=189_000,
        within_limit=False, requires_supervisor=True,
        pickup_code=code, created_at_epoch=epoch,
    ))

    # tech-brooks orders a restricted part; a supervisor approves it (real, via digest login).
    with httpx.Client(base_url=vuln_base_url, timeout=15.0) as brooks:
        _vlogin(brooks, "tech-brooks")
        created = brooks.post(
            "/api/orders", json=order, headers={"X-Ninebark-Signature": signature}
        )
        order_id = created.json()["id"]
        assert created.json()["state"] == "pending_supervisor"

    with httpx.Client(base_url=vuln_base_url, timeout=15.0) as sup:
        _vlogin(sup, "sup-navarro")
        approved = sup.post(f"/api/orders/{order_id}/approve")
        assert approved.status_code == 200
        assert approved.json()["state"] == "approved"

    # tech-avery enumerates the disclosed window and collects the peer's part.
    result = enumerate_pickup_attack(vuln_base_url, order_id)
    assert result.bound == 1000
    assert result.candidate_count == 1000
    assert result.accepted_code == code
    assert result.order_state == "collected"
    assert result.tried <= 43  # suffix 042 -> found on the 43rd candidate

    rendered = result.render()
    assert "bound: 1000" in rendered


def test_secure_pickup_rejects_a_derived_code(api: httpx.Client) -> None:
    res = api.post(
        "/api/login",
        json={"account_id": "tech-avery", "password": "avery-ninebark-demo"},
    )
    assert res.status_code == 200
    derived = f"PU-{int(time.time())}-000"
    refused = api.post("/api/pickup", json={"code": derived})
    assert refused.status_code == 403
    assert refused.json() == {"detail": "request_refused"}
