"""The embedded-signing-key sink, exercised directly against the vulnerable app.

A valid signature over false facts wins; a tampered body with a stale signature is refused,
proving the verification is correct and the flaw is the shipped key.
"""

from __future__ import annotations

import httpx

from keyjack.signing import DEMO_SIGNING_KEY, canonical_order_string, sign

DEMO_PASSWORDS = {
    "tech-avery": "avery-ninebark-demo",
    "tech-brooks": "brooks-ninebark-demo",
}


def vlogin(client: httpx.Client, account: str) -> None:
    res = client.post(
        "/api/login", json={"account_id": account, "password": DEMO_PASSWORDS[account]}
    )
    assert res.status_code == 200, res.text


def signature_for(order: dict[str, object]) -> str:
    return sign(
        DEMO_SIGNING_KEY,
        canonical_order_string(
            part_number=str(order["part_number"]),
            quantity=int(order["quantity"]),  # type: ignore[arg-type]
            work_order_id=str(order["work_order_id"]),
            unit_price_cents=int(order["unit_price_cents"]),  # type: ignore[arg-type]
            restricted=bool(order["restricted"]),
            line_total_cents=int(order["line_total_cents"]),  # type: ignore[arg-type]
        ),
    )


def test_forged_but_valid_order_is_auto_approved(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api, "tech-avery")
    # A restricted $1,890 part, signed with false price and restriction fields.
    order: dict[str, object] = {
        "part_number": "PN-7741",
        "quantity": 1,
        "work_order_id": "WO-1001",
        "unit_price_cents": 1,
        "restricted": False,
        "line_total_cents": 1,
    }
    res = vuln_api.post(
        "/api/orders", json=order, headers={"X-Ninebark-Signature": signature_for(order)}
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["state"] == "auto_approved"
    assert body["part_number"] == "PN-7741"
    assert body["restricted"] is False  # the server trusted the forged flag
    assert body["unit_price_cents"] == 1


def test_tampered_body_with_stale_signature_is_refused(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api, "tech-avery")
    order: dict[str, object] = {
        "part_number": "PN-7741",
        "quantity": 1,
        "work_order_id": "WO-1001",
        "unit_price_cents": 1,
        "restricted": False,
        "line_total_cents": 1,
    }
    stale = signature_for(order)
    tampered = {**order, "unit_price_cents": 189_000}  # change the body, keep the old signature
    res = vuln_api.post(
        "/api/orders", json=tampered, headers={"X-Ninebark-Signature": stale}
    )
    assert res.status_code == 400  # verification is correct — the failure is key placement


def test_missing_signature_is_refused(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api, "tech-avery")
    order = {
        "part_number": "PN-1002",
        "quantity": 1,
        "work_order_id": "WO-1001",
        "unit_price_cents": 3_800,
        "restricted": False,
        "line_total_cents": 3_800,
    }
    res = vuln_api.post("/api/orders", json=order)  # no signature header
    assert res.status_code == 400


def test_honest_signed_orders_route_correctly(vuln_api: httpx.Client) -> None:
    vlogin(vuln_api, "tech-avery")
    cheap: dict[str, object] = {
        "part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 3_800, "restricted": False, "line_total_cents": 3_800,
    }
    r1 = vuln_api.post(
        "/api/orders", json=cheap, headers={"X-Ninebark-Signature": signature_for(cheap)}
    )
    assert r1.json()["state"] == "auto_approved"

    restricted: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
    }
    r2 = vuln_api.post(
        "/api/orders", json=restricted,
        headers={"X-Ninebark-Signature": signature_for(restricted)},
    )
    assert r2.json()["state"] == "pending_supervisor"
