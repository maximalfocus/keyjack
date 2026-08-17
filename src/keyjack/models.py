"""SQLAlchemy 2.0 models for the fictional Ninebark Field Services parts-ordering domain.

State lives only in this database and is observed only through the application's own HTTP
surface — never read directly by the demonstration.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Role(enum.StrEnum):
    TECHNICIAN = "technician"
    SUPERVISOR = "supervisor"


class OrderState(enum.StrEnum):
    AUTO_APPROVED = "auto_approved"
    PENDING_SUPERVISOR = "pending_supervisor"
    APPROVED = "approved"
    REJECTED = "rejected"
    COLLECTED = "collected"


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)
    # Server-held approval limit in cents; NULL for supervisors (no self-limit).
    approval_limit_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Argon2id output for the secure credential path. Only the KDF output is stored.
    kdf_hash: Mapped[str] = mapped_column(String, nullable=False)


class Part(Base):
    __tablename__ = "parts"

    part_number: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    unit_price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    restricted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stock: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class WorkOrder(Base):
    __tablename__ = "work_orders"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=False)


class Order(Base):
    __tablename__ = "orders"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False)
    part_number: Mapped[str] = mapped_column(ForeignKey("parts.part_number"), nullable=False)
    work_order_id: Mapped[str] = mapped_column(ForeignKey("work_orders.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)
    # Server-derived snapshots — never taken from the request body.
    unit_price_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    line_total_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    restricted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    state: Mapped[OrderState] = mapped_column(Enum(OrderState), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    approved_by: Mapped[str | None] = mapped_column(
        ForeignKey("accounts.id"), nullable=True
    )
    collected_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    pickup_code: Mapped[PickupCode | None] = relationship(
        back_populates="order", uselist=False
    )


class PickupCode(Base):
    __tablename__ = "pickup_codes"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    # The secret pickup value. Server-issued (CSPRNG) in the secure application.
    code: Mapped[str] = mapped_column(String, nullable=False, index=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), nullable=False)
    owner_account_id: Mapped[str] = mapped_column(
        ForeignKey("accounts.id"), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    order: Mapped[Order] = relationship(back_populates="pickup_code")


class Session(Base):
    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("accounts.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    route: Mapped[str] = mapped_column(String, nullable=False)
    reason_code: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
