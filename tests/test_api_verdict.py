"""The client-computed verdict sink against the vulnerable app.

The client posts the authorization verdict and the server routes on it without recomputing.
Forging the verdict — with an honest price and a real restricted part — auto-approves the order.
"""

from __future__ import annotations

import httpx

from keyjack.hashing import sha256_hex
from keyjack.signing import DEMO_SIGNING_KEY, canonical_order_string, sign


def vlogin(client: httpx.Client) -> None:
    res = client.post(
        "/api/login",
        json={"account_id": "tech-avery",
              "password_digest": sha256_hex("avery-ninebark-demo")},
    )
    assert res.status_code == 200


def signed(order: dict[str, object]) -> str:
    return sign(
        DEMO_SIGNING_KEY,
        canonical_order_string(
            part_number=str(order["part_number"]),
            quantity=int(order["quantity"]),  # type: ignore[arg-type]
            work_order_id=str(order["work_order_id"]),
            unit_price_cents=int(order["unit_price_cents"]),  # type: ignore[arg-type]
            restricted=bool(order["restricted"]),
            line_total_cents=int(order["line_total_cents"]),  # type: ignore[arg-type]
            within_limit=order.get("within_limit"),  # type: ignore[arg-type]
            requires_supervisor=order.get("requires_supervisor"),  # type: ignore[arg-type]
        ),
    )


def test_forged_verdict_auto_approves_restricted_over_limit(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api)
    # Honest restricted $1,890 part, but a forged verdict claiming it is within limit.
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
        "within_limit": True, "requires_supervisor": False,
    }
    res = vuln_api.post(
        "/api/orders", json=order, headers={"X-Ninebark-Signature": signed(order)}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["state"] == "auto_approved"
    assert body["restricted"] is True  # a genuinely restricted part, auto-approved


def test_honest_verdict_still_routes_to_supervisor(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api)
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
        "within_limit": False, "requires_supervisor": True,
    }
    res = vuln_api.post(
        "/api/orders", json=order, headers={"X-Ninebark-Signature": signed(order)}
    )
    assert res.json()["state"] == "pending_supervisor"


def test_tampered_verdict_with_stale_signature_is_refused(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api)
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
        "within_limit": False, "requires_supervisor": True,
    }
    stale = signed(order)
    tampered = {**order, "within_limit": True, "requires_supervisor": False}
    res = vuln_api.post(
        "/api/orders", json=tampered, headers={"X-Ninebark-Signature": stale}
    )
    assert res.status_code == 400  # the verdict is covered by the signature
