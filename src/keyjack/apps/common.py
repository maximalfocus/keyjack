"""Shared application wiring used by every keyjack variant.

The secure and vulnerable applications serve the same model, authentication, read surface,
approval workflow, and pickup path. They differ only in the client they serve and in the
order-creation route — which is exactly where the client-side-crypto-misuse lesson lives.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
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
    REASON_ORDER_REJECTED,
    REASON_PICKUP_REFUSED,
    emit_audit,
    new_correlation_id,
)
from ..clock import utcnow
from ..config import Settings
from ..db import make_engine, make_session_factory
from ..fixtures import reset_and_seed
from ..models import Account, Base, Order, OrderState, Part, PickupCode, Role, WorkOrder
from ..models import Session as SessionRow
from ..schemas import (
    AccountOut,
    LoginRequest,
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


@dataclass
class AppRuntime:
    settings: Settings
    session_factory: sessionmaker[DbSession]
    hasher: PasswordHasher
    templates: Jinja2Templates


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


def new_order_id() -> str:
    return f"ORD-{new_session_token()[:10]}"


def configure_logging() -> None:
    audit_logger = logging.getLogger("keyjack.audit")
    if not audit_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False


def build_app(title: str, settings: Settings, client_subdir: str) -> tuple[FastAPI, AppRuntime]:
    """Create a FastAPI app with the database seeded and shared state wired.

    Each app serves **only** its own client under ``/static/app`` plus shared, key-free assets
    under ``/static/shared`` — so a variant never serves another variant's client source.
    """

    configure_logging()
    engine = make_engine(settings)
    session_factory = make_session_factory(engine)
    hasher = build_hasher(settings)

    if settings.reseed_on_startup:
        reset_and_seed(engine, session_factory, hasher)
    else:
        Base.metadata.create_all(engine)

    app = FastAPI(title=title, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.hasher = hasher
    # A decoy hash so an unknown account costs the same as a wrong password: no timing oracle.
    app.state.decoy_hash = hasher.hash("decoy-not-a-real-credential")

    app.mount("/static/shared", StaticFiles(directory=_WEB / "static" / "shared"),
              name="shared")
    app.mount("/static/app", StaticFiles(directory=_WEB / "static" / client_subdir),
              name="client")
    templates = Jinja2Templates(directory=str(_WEB / "templates"))
    return app, AppRuntime(settings, session_factory, hasher, templates)


def register_pages(
    app: FastAPI,
    rt: AppRuntime,
    *,
    vulnerable: bool,
    client_src: str,
    client_config_key: str | None = None,
) -> None:
    templates = rt.templates
    settings = rt.settings

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request, "app.html", {"vulnerable": vulnerable, "client_src": client_src}
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode}

    @app.get("/api/client-config")
    def client_config() -> dict[str, object]:
        # The secure and source-embedded-key clients are handed no key here. The half-fixed
        # variant "removes the key from the source" and serves it at runtime instead —
        # which changes nothing, because it still arrives at the client.
        config: dict[str, object] = {
            "app_name": "keyjack", "mode": settings.mode, "vulnerable": vulnerable
        }
        if client_config_key is not None:
            config["signing_key"] = client_config_key
        return config


def register_auth(app: FastAPI, rt: AppRuntime) -> None:
    settings = rt.settings

    @app.post("/api/login")
    async def login(request: Request, db: DbSession = Depends(get_db)) -> Response:
        hasher = _hasher(request)
        try:
            payload = await request.json()
            data = LoginRequest.model_validate(payload)
        except Exception:
            emit_audit(db, correlation_id=new_correlation_id(), actor="unknown",
                       route="/api/login", reason_code=REASON_LOGIN_FAILED)
            db.commit()
            raise GENERIC_401 from None

        account = db.get(Account, data.account_id)
        if account is None:
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


def register_reads(app: FastAPI, rt: AppRuntime) -> None:
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
        out = OrderDetailOut(**OrderOut.model_validate(order).model_dump(), pickup_code=None)
        if (
            order.account_id == actor.id
            and order.state in COLLECTABLE_STATES
            and order.pickup_code is not None
        ):
            out.pickup_code = order.pickup_code.code
        return out


def register_workflow(app: FastAPI, rt: AppRuntime) -> None:
    settings = rt.settings

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
