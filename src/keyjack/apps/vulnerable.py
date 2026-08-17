"""The intentionally vulnerable application (embedded signing key).

This variant is local educational material only. It is absent from the default Compose path
and refuses to start unless **both** a non-default Compose profile and an explicit environment
acknowledgement are present.

Its server verifies the request signature **correctly** and then **trusts the signed body** —
the price, the restriction, and the line total. Because the signing key is shipped to every
browser, anyone can produce a valid signature over false facts, so a restricted, over-limit
part is auto-approved. The failure is key placement, not broken verification.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from ..audit import REASON_ORDER_CREATED, emit_audit, new_correlation_id
from ..clock import utcnow
from ..config import Settings, load_settings
from ..domain import compute_authorization, route_state
from ..models import Account, Order, OrderState, Part, Role, WorkOrder
from ..schemas import OrderOut, SignedOrderRequest
from ..signing import DEMO_SIGNING_KEY, canonical_order_string, verify
from .common import (
    GENERIC_REFUSAL,
    build_app,
    current_actor,
    get_db,
    issue_pickup_code,
    new_order_id,
    register_auth,
    register_pages,
    register_reads,
    register_workflow,
)

ACK_ENV = "KEYJACK_ACK_VULNERABLE"
REQUIRED_ACK = "i-understand-this-is-intentionally-vulnerable"
SIGNATURE_HEADER = "X-Ninebark-Signature"


def _require_optin() -> None:
    """Refuse to start without the explicit acknowledgement (one of the two opt-in gates)."""

    if os.environ.get(ACK_ENV, "") != REQUIRED_ACK:
        raise RuntimeError(
            "Refusing to start the intentionally vulnerable application. Set "
            f"{ACK_ENV}={REQUIRED_ACK} and select the non-default 'vulnerable' Compose "
            "profile to run this local educational material."
        )


def create_vulnerable_app(settings: Settings | None = None) -> FastAPI:
    _require_optin()
    settings = settings or load_settings()
    app, rt = build_app("keyjack (VULNERABLE)", settings)
    register_pages(app, rt, vulnerable=True, client_src="/static/vulnerable/client.js")
    register_auth(app, rt)
    register_reads(app, rt)
    register_workflow(app, rt)

    @app.post("/api/orders")
    def create_order(
        body: SignedOrderRequest,
        request: Request,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderOut:
        if actor.role is not Role.TECHNICIAN or actor.approval_limit_cents is None:
            raise GENERIC_REFUSAL

        # Verify the signature correctly. A tampered body with a stale signature is rejected
        # here — proof that the verification is sound and the flaw is the shipped key alone.
        signature = request.headers.get(SIGNATURE_HEADER, "")
        canonical = canonical_order_string(
            part_number=body.part_number,
            quantity=body.quantity,
            work_order_id=body.work_order_id,
            unit_price_cents=body.unit_price_cents,
            restricted=body.restricted,
            line_total_cents=body.line_total_cents,
        )
        if not verify(DEMO_SIGNING_KEY, canonical, signature):
            raise HTTPException(status_code=400, detail="invalid_signature")

        part = db.get(Part, body.part_number)
        work_order = db.get(WorkOrder, body.work_order_id)
        if part is None or work_order is None or work_order.account_id != actor.id:
            raise GENERIC_REFUSAL

        # THE VULNERABILITY: trust the signed body's price, restriction, and line total
        # instead of the server's own catalog. A valid signature over false facts wins.
        authorization = compute_authorization(
            approval_limit_cents=actor.approval_limit_cents,
            restricted=body.restricted,
            line_total_cents=body.line_total_cents,
        )
        state = route_state(authorization)

        now = utcnow()
        order = Order(
            id=new_order_id(),
            account_id=actor.id,
            part_number=body.part_number,
            work_order_id=work_order.id,
            quantity=body.quantity,
            unit_price_cents=body.unit_price_cents,
            line_total_cents=body.line_total_cents,
            restricted=body.restricted,
            state=state,
            created_at=now,
        )
        db.add(order)
        if state is OrderState.AUTO_APPROVED:
            issue_pickup_code(db, order, now, settings.pickup_ttl_seconds)
        emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                   route="/api/orders", reason_code=REASON_ORDER_CREATED)
        db.commit()
        return OrderOut.model_validate(order)

    return app
