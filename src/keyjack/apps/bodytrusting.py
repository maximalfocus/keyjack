"""The body-trusting order route shared by the vulnerable and half-fixed applications.

It verifies the request signature correctly and then trusts the signed body: the price, the
restriction, the line total, and — when present — the client-computed authorization verdict.
The half-fixed variant delivers the key differently (at runtime, minified) but reuses this
exact route, which is why its remediations change nothing.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy.orm import Session as DbSession

from ..audit import REASON_ORDER_CREATED, emit_audit, new_correlation_id
from ..clock import utcnow
from ..domain import Authorization, compute_authorization, route_state
from ..models import Account, Order, OrderState, Part, Role, WorkOrder
from ..schemas import OrderOut, SignedOrderRequest
from ..signing import DEMO_SIGNING_KEY, canonical_order_string, verify
from .common import (
    GENERIC_REFUSAL,
    AppRuntime,
    current_actor,
    get_db,
    issue_pickup_code,
    new_order_id,
)

SIGNATURE_HEADER = "X-Ninebark-Signature"


def register_body_trusting_order_route(app: FastAPI, rt: AppRuntime) -> None:
    settings = rt.settings

    @app.post("/api/orders")
    def create_order(
        body: SignedOrderRequest,
        request: Request,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderOut:
        if actor.role is not Role.TECHNICIAN or actor.approval_limit_cents is None:
            raise GENERIC_REFUSAL

        # Correct verification: the signature covers the whole body (verdict included when
        # present). A tampered body with a stale signature is rejected here.
        signature = request.headers.get(SIGNATURE_HEADER, "")
        canonical = canonical_order_string(
            part_number=body.part_number,
            quantity=body.quantity,
            work_order_id=body.work_order_id,
            unit_price_cents=body.unit_price_cents,
            restricted=body.restricted,
            line_total_cents=body.line_total_cents,
            within_limit=body.within_limit,
            requires_supervisor=body.requires_supervisor,
        )
        if not verify(DEMO_SIGNING_KEY, canonical, signature):
            raise HTTPException(status_code=400, detail="invalid_signature")

        part = db.get(Part, body.part_number)
        work_order = db.get(WorkOrder, body.work_order_id)
        if part is None or work_order is None or work_order.account_id != actor.id:
            raise GENERIC_REFUSAL

        # THE VULNERABILITY. Trust the signed body. If the client posted a verdict, route on
        # it directly (the verdict sink); otherwise compute it from the trusted — but forged —
        # price and restriction (the signing-key sink).
        if body.within_limit is not None and body.requires_supervisor is not None:
            authorization = Authorization(
                within_limit=body.within_limit,
                requires_supervisor=body.requires_supervisor,
            )
        else:
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
