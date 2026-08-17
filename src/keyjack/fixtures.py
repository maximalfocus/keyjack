"""Deterministic seed data for the fictional Ninebark Field Services organisation.

Every identifier, name, price, and credential here is conspicuously fictional demonstration
data. A fresh run reseeds identical reference state; orders are created during the walkthrough.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from .hashing import sha256_hex
from .models import Account, Base, Part, Role, WorkOrder
from .security import hash_password

# Demo-only credentials for the three fixture accounts. Fictional; not real secrets.
DEMO_PASSWORDS: dict[str, str] = {
    "tech-avery": "avery-ninebark-demo",
    "tech-brooks": "brooks-ninebark-demo",
    "sup-navarro": "navarro-ninebark-demo",
}

# A checked-in fictional fixture: the exact SHA-256 digest the supervisor's browser computes
# and posts to the vulnerable app. The demonstration replays this value — nothing is cracked.
CAPTURED_SUPERVISOR_DIGEST = (
    "5c522054065bac54624ac2c84cc76739682fe1b36f49a64f5a4cfbdd37f39881"
)

TECHNICIAN_LIMIT_CENTS = 25_000  # $250.00 server-held approval limit.


def _account(
    hasher: PasswordHasher, account_id: str, display_name: str, role: Role,
    limit: int | None,
) -> Account:
    password = DEMO_PASSWORDS[account_id]
    return Account(
        id=account_id,
        display_name=display_name,
        role=role,
        approval_limit_cents=limit,
        kdf_hash=hash_password(hasher, password),
        sha256_digest=sha256_hex(password),
    )


def _accounts(hasher: PasswordHasher) -> list[Account]:
    return [
        _account(hasher, "tech-avery", "Avery (Technician)", Role.TECHNICIAN,
                 TECHNICIAN_LIMIT_CENTS),
        _account(hasher, "tech-brooks", "Brooks (Technician)", Role.TECHNICIAN,
                 TECHNICIAN_LIMIT_CENTS),
        _account(hasher, "sup-navarro", "Navarro (Supervisor)", Role.SUPERVISOR, None),
    ]


def _parts() -> list[Part]:
    return [
        Part(part_number="PN-2210", name="Torque wrench", unit_price_cents=12_000,
             restricted=False, stock=12),
        Part(part_number="PN-1002", name="Hex bolt assortment", unit_price_cents=3_800,
             restricted=False, stock=50),
        Part(part_number="PN-3300", name="Field diagnostic tablet", unit_price_cents=42_000,
             restricted=False, stock=5),
        Part(part_number="PN-5533", name="Refrigerant canister", unit_price_cents=22_000,
             restricted=True, stock=8),
        Part(part_number="PN-7741", name="Thermal imaging module", unit_price_cents=189_000,
             restricted=True, stock=3),
    ]


def _work_orders() -> list[WorkOrder]:
    return [
        WorkOrder(id="WO-1001", account_id="tech-avery",
                  description="Rooftop HVAC inspection — Birchwood site"),
        WorkOrder(id="WO-1002", account_id="tech-brooks",
                  description="Cold storage compressor service — Alderway depot"),
    ]


def seed(session: Session, hasher: PasswordHasher) -> None:
    """Insert the deterministic reference fixtures into an empty schema."""

    session.add_all(_accounts(hasher))
    session.add_all(_parts())
    session.add_all(_work_orders())
    session.commit()


def reset_and_seed(
    engine: Engine, session_factory: sessionmaker[Session], hasher: PasswordHasher
) -> None:
    """Drop all tables, recreate the schema, and reseed identical reference state."""

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with session_factory() as session:
        seed(session, hasher)
