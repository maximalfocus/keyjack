"""The secure application.

Every security-relevant fact is re-derived by the server from state it holds: the price and
restriction from its own catalog, the authorization verdict from the authenticated actor's
server-held limit, the credential from a server-side KDF, and the pickup code from a CSPRNG.
The browser is handed no secret by any path.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session as DbSession

from ..audit import REASON_ORDER_CREATED, emit_audit, new_correlation_id
from ..clock import utcnow
from ..config import Settings, load_settings
from ..domain import compute_authorization, route_state
from ..models import Account, Order, OrderState, Part, Role, WorkOrder
from ..schemas import OrderCreateRequest, OrderOut
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


def create_secure_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app, rt = build_app("keyjack (secure)", settings, "secure")
    register_pages(app, rt, vulnerable=False, client_src="/static/app/client.js")
    register_auth(app, rt)
    register_reads(app, rt)
    register_workflow(app, rt)

    @app.post("/api/orders")
    def create_order(
        body: OrderCreateRequest,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderOut:
        if actor.role is not Role.TECHNICIAN or actor.approval_limit_cents is None:
            raise GENERIC_REFUSAL
        part = db.get(Part, body.part_number)
        work_order = db.get(WorkOrder, body.work_order_id)
        if part is None or work_order is None or work_order.account_id != actor.id:
            raise GENERIC_REFUSAL

        # Server-derived facts only. Any price/restriction/authorization/signature in the
        # request body was ignored by the schema and never consulted here.
        unit_price = part.unit_price_cents
        line_total = unit_price * body.quantity
        authorization = compute_authorization(
            approval_limit_cents=actor.approval_limit_cents,
            restricted=part.restricted,
            line_total_cents=line_total,
        )
        state = route_state(authorization)

        now = utcnow()
        order = Order(
            id=new_order_id(),
            account_id=actor.id,
            part_number=part.part_number,
            work_order_id=work_order.id,
            quantity=body.quantity,
            unit_price_cents=unit_price,
            line_total_cents=line_total,
            restricted=part.restricted,
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
