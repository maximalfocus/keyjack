"""API-level acceptance tests through the real HTTP boundary against the running app."""

from __future__ import annotations

import httpx
import pytest

DEMO_PASSWORDS = {
    "tech-avery": "avery-ninebark-demo",
    "tech-brooks": "brooks-ninebark-demo",
    "sup-navarro": "navarro-ninebark-demo",
}

UNAUTHORIZED = {"detail": "unauthorized"}
REFUSED = {"detail": "request_refused"}


def login(api: httpx.Client, account_id: str) -> None:
    res = api.post(
        "/api/login",
        json={"account_id": account_id, "password": DEMO_PASSWORDS[account_id]},
    )
    assert res.status_code == 200, res.text


def part_stock(api: httpx.Client, part_number: str) -> int:
    parts = api.get("/api/catalog").json()
    return next(p["stock"] for p in parts if p["part_number"] == part_number)


def test_health_and_client_config_ship_no_key(api: httpx.Client) -> None:
    assert api.get("/health").json()["mode"] == "secure"
    # The runtime config the client can fetch carries no key or signing material at all.
    config = api.get("/api/client-config").json()
    assert config == {"app_name": "keyjack", "mode": "secure", "vulnerable": False}


@pytest.mark.parametrize("account_id", ["tech-avery", "tech-brooks", "sup-navarro"])
def test_valid_login(api: httpx.Client, account_id: str) -> None:
    login(api, account_id)
    me = api.get("/api/me").json()
    assert me["id"] == account_id


@pytest.mark.parametrize(
    "payload",
    [
        {},  # missing both
        {"account_id": "tech-avery"},  # missing password
        {"account_id": "ghost", "password": "x"},  # unknown account
        {"account_id": "tech-avery", "password": "wrong"},  # wrong password
    ],
)
def test_bad_credentials_are_uniform_401(api: httpx.Client, payload: dict[str, str]) -> None:
    res = api.post("/api/login", json=payload)
    assert res.status_code == 401
    assert res.json() == UNAUTHORIZED


def test_malformed_body_is_also_uniform_401(api: httpx.Client) -> None:
    res = api.post(
        "/api/login", content="{ not json", headers={"Content-Type": "application/json"}
    )
    assert res.status_code == 401
    assert res.json() == UNAUTHORIZED


@pytest.mark.parametrize(
    ("part_number", "quantity", "expected_state"),
    [
        ("PN-1002", 1, "auto_approved"),  # $38 unrestricted, under limit
        ("PN-3300", 1, "pending_supervisor"),  # $420 unrestricted, over limit
        ("PN-5533", 1, "pending_supervisor"),  # $220 restricted, under limit
        ("PN-7741", 1, "pending_supervisor"),  # $1890 restricted, over limit
    ],
)
def test_order_routing_matrix(
    api: httpx.Client, part_number: str, quantity: int, expected_state: str
) -> None:
    login(api, "tech-avery")
    res = api.post(
        "/api/orders",
        json={"part_number": part_number, "quantity": quantity, "work_order_id": "WO-1001"},
    )
    assert res.status_code == 200
    assert res.json()["state"] == expected_state


def test_smuggled_fields_are_ignored_not_rejected(api: httpx.Client) -> None:
    login(api, "tech-avery")
    # A forged-style body: false price, false restriction, a client verdict, a signature.
    res = api.post(
        "/api/orders",
        json={
            "part_number": "PN-7741",
            "quantity": 1,
            "work_order_id": "WO-1001",
            "unit_price_cents": 1,
            "restricted": False,
            "authorization": {"within_limit": True, "requires_supervisor": False},
        },
        headers={"X-Ninebark-Signature": "deadbeef"},
    )
    assert res.status_code == 200
    body = res.json()
    # Server-derived facts win; the smuggled values were silently ignored.
    assert body["state"] == "pending_supervisor"
    assert body["unit_price_cents"] == 189_000
    assert body["restricted"] is True


def test_order_requires_owned_work_order(api: httpx.Client) -> None:
    login(api, "tech-avery")
    res = api.post(
        "/api/orders",
        json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1002"},
    )
    assert res.status_code == 403
    assert res.json() == REFUSED


def test_role_boundaries(api: httpx.Client) -> None:
    # A supervisor cannot place an order.
    login(api, "sup-navarro")
    res = api.post(
        "/api/orders",
        json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1001"},
    )
    assert res.status_code == 403


def test_technician_cannot_approve(api: httpx.Client) -> None:
    login(api, "tech-avery")
    order = api.post(
        "/api/orders",
        json={"part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001"},
    ).json()
    res = api.post(f"/api/orders/{order['id']}/approve")
    assert res.status_code == 403


def test_full_supervisor_flow_and_single_use_pickup(api: httpx.Client) -> None:
    login(api, "tech-avery")
    stock_before = part_stock(api, "PN-7741")
    order = api.post(
        "/api/orders",
        json={"part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001"},
    ).json()
    assert order["state"] == "pending_supervisor"
    # The owner cannot yet see a code (none issued until approval).
    assert api.get(f"/api/orders/{order['id']}").json()["pickup_code"] is None

    with httpx.Client(base_url=str(api.base_url), timeout=15.0) as sup:
        login(sup, "sup-navarro")
        approved = sup.post(f"/api/orders/{order['id']}/approve")
        assert approved.status_code == 200
        assert approved.json()["state"] == "approved"

    detail = api.get(f"/api/orders/{order['id']}").json()
    code = detail["pickup_code"]
    assert code and code.startswith("NB-")

    collected = api.post("/api/pickup", json={"code": code})
    assert collected.status_code == 200
    assert collected.json()["state"] == "collected"
    assert part_stock(api, "PN-7741") == stock_before - 1

    # Single use: the same code is now refused, and inventory does not move again.
    again = api.post("/api/pickup", json={"code": code})
    assert again.status_code == 403
    assert again.json() == REFUSED
    assert part_stock(api, "PN-7741") == stock_before - 1


def test_auto_approved_order_is_collectable(api: httpx.Client) -> None:
    login(api, "tech-avery")
    order = api.post(
        "/api/orders",
        json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1001"},
    ).json()
    assert order["state"] == "auto_approved"
    code = api.get(f"/api/orders/{order['id']}").json()["pickup_code"]
    assert code
    assert api.post("/api/pickup", json={"code": code}).json()["state"] == "collected"


def test_pickup_refusals_are_uniform(api: httpx.Client) -> None:
    # Unknown code.
    login(api, "tech-avery")
    unknown = api.post("/api/pickup", json={"code": "NB-does-not-exist"})
    assert unknown.status_code == 403
    assert unknown.json() == REFUSED

    # Wrong-owner: brooks approves-and-owns nothing here, so build avery's code then
    # present it as brooks.
    login(api, "tech-brooks")
    b_order = api.post(
        "/api/orders",
        json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1002"},
    ).json()
    b_code = api.get(f"/api/orders/{b_order['id']}").json()["pickup_code"]

    with httpx.Client(base_url=str(api.base_url), timeout=15.0) as avery:
        login(avery, "tech-avery")
        wrong_owner = avery.post("/api/pickup", json={"code": b_code})
        assert wrong_owner.status_code == 403
        assert wrong_owner.json() == REFUSED


def test_shared_queue_is_readable(api: httpx.Client) -> None:
    login(api, "tech-avery")
    api.post(
        "/api/orders",
        json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1001"},
    )
    login(api, "tech-brooks")
    queue = api.get("/api/orders")
    assert queue.status_code == 200
    assert isinstance(queue.json(), list)


def test_protected_routes_require_auth(api: httpx.Client) -> None:
    for path in ("/api/me", "/api/catalog", "/api/orders", "/api/work-orders"):
        assert api.get(path).status_code == 401
