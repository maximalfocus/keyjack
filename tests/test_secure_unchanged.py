"""The secure app is untouched by the identical forged request.

Against the secure app the forged signature is meaningless and the smuggled fields are
ignored (not rejected loudly): the restricted part is routed to supervisor review, the
settled order/approval state and the inventory are byte-for-byte unchanged, and exactly one
audit event is emitted.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from keyjack.apps.secure import create_secure_app
from keyjack.config import Settings
from keyjack.signing import DEMO_SIGNING_KEY, canonical_order_string, sign

FORGED_ORDER: dict[str, object] = {
    "part_number": "PN-7741",
    "quantity": 1,
    "work_order_id": "WO-1001",
    "unit_price_cents": 1,
    "restricted": False,
    "line_total_cents": 1,
}
FORGED_SIG = sign(
    DEMO_SIGNING_KEY,
    canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1001",
        unit_price_cents=1, restricted=False, line_total_cents=1,
    ),
)


def _settled_and_stock(get: object) -> tuple[list[tuple[str, str]], list[tuple[str, int]]]:
    orders = get("/api/orders").json()  # type: ignore[operator]
    catalog = get("/api/catalog").json()  # type: ignore[operator]
    settled = sorted(
        (o["id"], o["state"]) for o in orders
        if o["state"] in {"auto_approved", "approved", "collected"}
    )
    stock = sorted((p["part_number"], p["stock"]) for p in catalog)
    return settled, stock


def test_forged_request_leaves_secure_settled_state_unchanged(api: httpx.Client) -> None:
    res = api.post(
        "/api/login",
        json={"account_id": "tech-avery", "password": "avery-ninebark-demo"},
    )
    assert res.status_code == 200
    before = _settled_and_stock(api.get)

    forged = api.post(
        "/api/orders", json=FORGED_ORDER, headers={"X-Ninebark-Signature": FORGED_SIG}
    )
    assert forged.status_code == 200
    body = forged.json()
    # Server-derived facts win: the restricted part goes to supervisor review, not auto-approval.
    assert body["state"] == "pending_supervisor"
    assert body["restricted"] is True
    assert body["unit_price_cents"] == 189_000

    after = _settled_and_stock(api.get)
    assert before == after  # settled orders and inventory byte-for-byte unchanged


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def secure_inprocess(tmp_path: object) -> Iterator[TestClient]:
    settings = Settings(
        db_url=f"sqlite+pysqlite:///{tmp_path}/kj.db",  # type: ignore[str-bytes-safe]
        argon2_time_cost=1, argon2_memory_cost_kib=8 * 1024, argon2_parallelism=1,
    )
    with TestClient(create_secure_app(settings)) as client:
        yield client


def test_forged_request_emits_exactly_one_audit_event(secure_inprocess: TestClient) -> None:
    secure_inprocess.post(
        "/api/login", json={"account_id": "tech-avery", "password": "avery-ninebark-demo"}
    )
    capture = _Capture()
    audit_logger = logging.getLogger("keyjack.audit")
    audit_logger.addHandler(capture)
    try:
        res = secure_inprocess.post(
            "/api/orders", json=FORGED_ORDER, headers={"X-Ninebark-Signature": FORGED_SIG}
        )
        assert res.status_code == 200
    finally:
        audit_logger.removeHandler(capture)
    assert len(capture.messages) == 1
