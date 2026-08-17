"""Pure authorization and routing logic.

These functions are the single source of truth the *secure* server uses to decide an
order's fate. The vulnerable contrast (added later) delegates the very same decision to
the browser; keeping the logic here, server-side, is the whole control.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import OrderState


@dataclass(frozen=True)
class Authorization:
    within_limit: bool
    requires_supervisor: bool


def compute_authorization(
    *, approval_limit_cents: int, restricted: bool, line_total_cents: int
) -> Authorization:
    """Recompute the authorization verdict from server-held facts only."""

    within_limit = line_total_cents <= approval_limit_cents
    requires_supervisor = restricted or not within_limit
    return Authorization(within_limit=within_limit, requires_supervisor=requires_supervisor)


def route_state(authorization: Authorization) -> OrderState:
    """Map an authorization verdict to the resulting order state."""

    if authorization.requires_supervisor:
        return OrderState.PENDING_SUPERVISOR
    return OrderState.AUTO_APPROVED
