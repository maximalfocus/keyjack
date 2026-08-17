"""In-process white-box tests: credential storage, log hygiene, and pickup-code expiry.

These drive the real ``create_secure_app`` through Starlette's TestClient so they can inspect
the audit log stream and the stored rows directly — things the network boundary hides.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from keyjack.apps.secure import create_secure_app
from keyjack.clock import utcnow
from keyjack.config import Settings
from keyjack.fixtures import DEMO_PASSWORDS
from keyjack.models import Account, PickupCode


@pytest.fixture
def app_client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        db_url=f"sqlite+pysqlite:///{tmp_path / 'keyjack-test.db'}",
        reseed_on_startup=True,
        argon2_time_cost=1,
        argon2_memory_cost_kib=8 * 1024,
        argon2_parallelism=1,
    )
    with TestClient(create_secure_app(settings)) as client:
        yield client


def _login(client: TestClient, account_id: str) -> None:
    res = client.post(
        "/api/login",
        json={"account_id": account_id, "password": DEMO_PASSWORDS[account_id]},
    )
    assert res.status_code == 200


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_only_kdf_output_is_stored(app_client: TestClient) -> None:
    factory = app_client.app.state.session_factory  # type: ignore[attr-defined]
    with factory() as db:
        accounts = db.execute(select(Account)).scalars().all()
        assert accounts
        for account in accounts:
            assert account.kdf_hash.startswith("$argon2id$")
            # No plaintext demo password is stored anywhere on the account row.
            assert DEMO_PASSWORDS[account.id] not in account.kdf_hash


def test_no_secret_appears_in_audit_log(app_client: TestClient) -> None:
    capture = _Capture()
    audit_logger = logging.getLogger("keyjack.audit")
    audit_logger.addHandler(capture)
    try:
        bad = app_client.post(
            "/api/login", json={"account_id": "sup-navarro", "password": "wrong"}
        )
        assert bad.status_code == 401
        _login(app_client, "tech-avery")
        order = app_client.post(
            "/api/orders",
            json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1001"},
        ).json()
        pickup_code = app_client.get(f"/api/orders/{order['id']}").json()["pickup_code"]
        assert pickup_code
        app_client.post("/api/pickup", json={"code": pickup_code})
    finally:
        audit_logger.removeHandler(capture)

    session_token = app_client.cookies.get("kj_session")
    blob = "\n".join(capture.messages)
    assert blob, "expected audit events to be emitted"
    for secret in [*DEMO_PASSWORDS.values(), pickup_code, session_token]:
        assert secret is None or secret not in blob


def test_expired_pickup_code_is_refused(app_client: TestClient) -> None:
    _login(app_client, "tech-avery")
    order = app_client.post(
        "/api/orders",
        json={"part_number": "PN-1002", "quantity": 1, "work_order_id": "WO-1001"},
    ).json()
    code = app_client.get(f"/api/orders/{order['id']}").json()["pickup_code"]

    factory = app_client.app.state.session_factory  # type: ignore[attr-defined]
    with factory() as db:
        row = db.execute(select(PickupCode).where(PickupCode.code == code)).scalars().one()
        row.expires_at = utcnow().replace(year=2000)
        db.commit()

    refused = app_client.post("/api/pickup", json={"code": code})
    assert refused.status_code == 403
    assert refused.json() == {"detail": "request_refused"}
