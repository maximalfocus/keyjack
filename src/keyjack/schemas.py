"""Request and response schemas.

The secure order schema accepts order *intent* only. Extra body fields — a smuggled price,
a client authorization verdict, a signature — are silently ignored (Pydantic's default),
never rejected loudly, so no response names a field or reveals which value was disregarded.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    account_id: str
    password: str


class OrderCreateRequest(BaseModel):
    part_number: str
    quantity: int = Field(gt=0)
    work_order_id: str


class PickupRequest(BaseModel):
    code: str


class SignedOrderRequest(BaseModel):
    """The vulnerable app's order body: the client signs price/restriction/total and the
    server trusts them once the signature verifies. Forgeable by anyone holding the key.

    ``within_limit`` / ``requires_supervisor`` are the optional client-computed verdict: when
    present, the vulnerable server routes on them instead of recomputing (the verdict sink)."""

    part_number: str
    quantity: int = Field(gt=0)
    work_order_id: str
    unit_price_cents: int
    restricted: bool
    line_total_cents: int
    within_limit: bool | None = None
    requires_supervisor: bool | None = None


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    display_name: str
    role: str
    approval_limit_cents: int | None


class PartOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    part_number: str
    name: str
    unit_price_cents: int
    restricted: bool
    stock: int


class WorkOrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    account_id: str
    description: str


class OrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    account_id: str
    part_number: str
    work_order_id: str
    quantity: int
    unit_price_cents: int
    line_total_cents: int
    restricted: bool
    state: str
    created_at: datetime
    approved_by: str | None
    collected_at: datetime | None


class OrderDetailOut(OrderOut):
    # The owner-only pickup code, present only when the requester owns an approved order.
    pickup_code: str | None = None
