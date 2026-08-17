"""The secure application.

Every security-relevant fact is re-derived by the server from state it holds: the price and
restriction from its own catalog, the authorization verdict from the authenticated actor's
server-held limit, the credential from a server-side KDF, and the pickup code from a CSPRNG.
The browser is handed no secret by any path.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

from argon2 import PasswordHasher
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from ..audit import (
    REASON_LOGIN_FAILED,
    REASON_ORDER_APPROVED,
    REASON_ORDER_COLLECTED,
    REASON_ORDER_CREATED,
    REASON_ORDER_REJECTED,
    REASON_PICKUP_REFUSED,
    emit_audit,
    new_correlation_id,
)
from ..clock import utcnow
from ..config import Settings, load_settings
from ..db import make_engine, make_session_factory
from ..domain import compute_authorization, route_state
from ..fixtures import reset_and_seed
from ..models import (
    Account,
    Base,
    Order,
    OrderState,
    Part,
    PickupCode,
    Role,
    WorkOrder,
)
from ..models import Session as SessionRow
from ..schemas import (
    AccountOut,
    LoginRequest,
    OrderCreateRequest,
    OrderDetailOut,
    OrderOut,
    PartOut,
    PickupRequest,
    WorkOrderOut,
)
from ..security import build_hasher, new_pickup_code, new_session_token, verify_password

_WEB = Path(__file__).resolve().parent.parent / "web"
SESSION_COOKIE = "kj_session"

# Uniform anti-oracle responses. No body names a field or reveals which control refused.
GENERIC_401 = HTTPException(status_code=401, detail="unauthorized")
GENERIC_REFUSAL = HTTPException(status_code=403, detail="request_refused")

# States from which an owner may collect an order with its server-issued pickup code.
COLLECTABLE_STATES = frozenset({OrderState.AUTO_APPROVED, OrderState.APPROVED})


def issue_pickup_code(
    db: DbSession, order: Order, now: datetime, ttl_seconds: int
) -> None:
    """Attach a fresh single-use, order- and owner-bound CSPRNG pickup code to an order."""

    db.add(
        PickupCode(
            id=new_session_token()[:12],
            code=new_pickup_code(),
            order_id=order.id,
            owner_account_id=order.account_id,
            used=False,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
    )


def _session_factory(request: Request) -> sessionmaker[DbSession]:
    return cast("sessionmaker[DbSession]", request.app.state.session_factory)


def _hasher(request: Request) -> PasswordHasher:
    return cast(PasswordHasher, request.app.state.hasher)


def get_db(request: Request) -> Iterator[DbSession]:
    db = _session_factory(request)()
    try:
        yield db
    finally:
        db.close()


def _lookup_actor(request: Request, db: DbSession) -> Account | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    row = db.get(SessionRow, token)
    if row is None or row.expires_at < utcnow():
        return None
    return db.get(Account, row.account_id)


def current_actor(request: Request, db: DbSession = Depends(get_db)) -> Account:
    actor = _lookup_actor(request, db)
    if actor is None:
        raise GENERIC_401
    return actor


def _configure_logging() -> None:
    audit_logger = logging.getLogger("keyjack.audit")
    if not audit_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False


def create_secure_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    _configure_logging()

    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    hasher = build_hasher(settings)

    if settings.reseed_on_startup:
        reset_and_seed(engine, session_factory, hasher)
    else:
        Base.metadata.create_all(engine)

    app = FastAPI(title="keyjack (secure)", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.hasher = hasher
    # A decoy hash so an unknown account costs the same as a wrong password: no timing oracle.
    app.state.decoy_hash = hasher.hash("decoy-not-a-real-credential")

    app.mount("/static", StaticFiles(directory=_WEB / "static"), name="static")
    templates = Jinja2Templates(directory=str(_WEB / "templates"))

    # ---- pages -------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "app.html", {"vulnerable": False})

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode}

    @app.get("/api/client-config")
    def client_config() -> dict[str, object]:
        # The secure client is handed no key, secret, or signing material by any path.
        return {"app_name": "keyjack", "mode": "secure", "vulnerable": False}

    # ---- auth --------------------------------------------------------------------

    @app.post("/api/login")
    async def login(request: Request, db: DbSession = Depends(get_db)) -> Response:
        hasher = _hasher(request)
        try:
            payload = await request.json()
            data = LoginRequest.model_validate(payload)
        except Exception:
            # Missing or malformed credentials get the same generic 401 as a wrong one.
            emit_audit(db, correlation_id=new_correlation_id(), actor="unknown",
                       route="/api/login", reason_code=REASON_LOGIN_FAILED)
            db.commit()
            raise GENERIC_401 from None

        account = db.get(Account, data.account_id)
        if account is None:
            # Verify against a decoy to equalise timing; the result is discarded.
            verify_password(hasher, cast(str, request.app.state.decoy_hash), data.password)
            ok = False
        else:
            ok = verify_password(hasher, account.kdf_hash, data.password)

        if not ok or account is None:
            emit_audit(db, correlation_id=new_correlation_id(), actor=data.account_id,
                       route="/api/login", reason_code=REASON_LOGIN_FAILED)
            db.commit()
            raise GENERIC_401

        now = utcnow()
        token = new_session_token()
        db.add(SessionRow(token=token, account_id=account.id, created_at=now,
                          expires_at=now + timedelta(seconds=settings.session_ttl_seconds)))
        db.commit()
        resp = JSONResponse(AccountOut.model_validate(account).model_dump())
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", path="/")
        return resp

    @app.post("/api/logout")
    def logout(request: Request, db: DbSession = Depends(get_db)) -> Response:
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            row = db.get(SessionRow, token)
            if row is not None:
                db.delete(row)
                db.commit()
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/me")
    def me(actor: Account = Depends(current_actor)) -> AccountOut:
        return AccountOut.model_validate(actor)

    # ---- catalog & work orders ---------------------------------------------------

    @app.get("/api/catalog")
    def catalog(
        db: DbSession = Depends(get_db), actor: Account = Depends(current_actor)
    ) -> list[PartOut]:
        parts = db.execute(select(Part).order_by(Part.part_number)).scalars().all()
        return [PartOut.model_validate(p) for p in parts]

    @app.get("/api/work-orders")
    def work_orders(
        db: DbSession = Depends(get_db), actor: Account = Depends(current_actor)
    ) -> list[WorkOrderOut]:
        rows = db.execute(
            select(WorkOrder).where(WorkOrder.account_id == actor.id)
        ).scalars().all()
        return [WorkOrderOut.model_validate(w) for w in rows]

    # ---- orders ------------------------------------------------------------------

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
            id=f"ORD-{new_session_token()[:10]}",
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
            # An auto-approved order is immediately collectable with a server-issued code.
            issue_pickup_code(db, order, now, settings.pickup_ttl_seconds)
        emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                   route="/api/orders", reason_code=REASON_ORDER_CREATED)
        db.commit()
        return OrderOut.model_validate(order)

    @app.get("/api/orders")
    def list_orders(
        db: DbSession = Depends(get_db), actor: Account = Depends(current_actor)
    ) -> list[OrderOut]:
        # A shared team queue any authenticated technician may read.
        rows = db.execute(select(Order).order_by(Order.created_at)).scalars().all()
        return [OrderOut.model_validate(o) for o in rows]

    @app.get("/api/orders/{order_id}")
    def get_order(
        order_id: str,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderDetailOut:
        order = db.get(Order, order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="not_found")
        # Build from the flat schema so the ORM pickup-code relationship is not read into
        # the string field; then disclose the code only to the owner of a collectable order.
        out = OrderDetailOut(**OrderOut.model_validate(order).model_dump(), pickup_code=None)
        if (
            order.account_id == actor.id
            and order.state in COLLECTABLE_STATES
            and order.pickup_code is not None
        ):
            out.pickup_code = order.pickup_code.code
        return out

    @app.post("/api/orders/{order_id}/approve")
    def approve_order(
        order_id: str,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderOut:
        if actor.role is not Role.SUPERVISOR:
            raise GENERIC_REFUSAL
        order = db.get(Order, order_id)
        if order is None or order.state is not OrderState.PENDING_SUPERVISOR:
            raise GENERIC_REFUSAL
        now = utcnow()
        order.state = OrderState.APPROVED
        order.approved_by = actor.id
        issue_pickup_code(db, order, now, settings.pickup_ttl_seconds)
        emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                   route="/api/orders/approve", reason_code=REASON_ORDER_APPROVED)
        db.commit()
        return OrderOut.model_validate(order)

    @app.post("/api/orders/{order_id}/reject")
    def reject_order(
        order_id: str,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderOut:
        if actor.role is not Role.SUPERVISOR:
            raise GENERIC_REFUSAL
        order = db.get(Order, order_id)
        if order is None or order.state is not OrderState.PENDING_SUPERVISOR:
            raise GENERIC_REFUSAL
        order.state = OrderState.REJECTED
        order.approved_by = actor.id
        emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                   route="/api/orders/reject", reason_code=REASON_ORDER_REJECTED)
        db.commit()
        return OrderOut.model_validate(order)

    # ---- pickup ------------------------------------------------------------------

    @app.post("/api/pickup")
    def pickup(
        body: PickupRequest,
        db: DbSession = Depends(get_db),
        actor: Account = Depends(current_actor),
    ) -> OrderOut:
        now = utcnow()
        row = db.execute(
            select(PickupCode).where(PickupCode.code == body.code)
        ).scalars().first()
        # A single uniform refusal for used, expired, wrong-owner, or unknown codes.
        if (
            row is None
            or row.used
            or row.expires_at < now
            or row.owner_account_id != actor.id
        ):
            emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                       route="/api/pickup", reason_code=REASON_PICKUP_REFUSED)
            db.commit()
            raise GENERIC_REFUSAL

        order = db.get(Order, row.order_id)
        if order is None or order.state not in COLLECTABLE_STATES:
            emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                       route="/api/pickup", reason_code=REASON_PICKUP_REFUSED)
            db.commit()
            raise GENERIC_REFUSAL

        part = db.get(Part, order.part_number)
        if part is not None:
            part.stock -= order.quantity  # decrement exactly once on collection
        row.used = True
        order.state = OrderState.COLLECTED
        order.collected_at = now
        emit_audit(db, correlation_id=new_correlation_id(), actor=actor.id,
                   route="/api/pickup", reason_code=REASON_ORDER_COLLECTED)
        db.commit()
        return OrderOut.model_validate(order)

    return app
