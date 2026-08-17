"""Structured audit events.

An audit event carries only a correlation id, the actor, the route, and a stable reason
code. The emitting function accepts no other data, so a secret, digest, password, session
token, or PII cannot structurally reach a log line or an audit row through this path.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session as DbSession

from .models import AuditEvent

_logger = logging.getLogger("keyjack.audit")

# Stable reason codes. Deliberately coarse so no code reveals which control refused.
REASON_LOGIN_FAILED = "login_failed"
REASON_PICKUP_REFUSED = "pickup_refused"
REASON_REQUEST_REFUSED = "request_refused"
REASON_ORDER_CREATED = "order_created"
REASON_ORDER_APPROVED = "order_approved"
REASON_ORDER_REJECTED = "order_rejected"
REASON_ORDER_COLLECTED = "order_collected"


def emit_audit(
    db: DbSession,
    *,
    correlation_id: str,
    actor: str,
    route: str,
    reason_code: str,
) -> AuditEvent:
    """Persist and log exactly one audit event from a fixed set of safe fields."""

    event = AuditEvent(
        id=secrets.token_hex(16),
        correlation_id=correlation_id,
        actor=actor,
        route=route,
        reason_code=reason_code,
        created_at=datetime.now(UTC),
    )
    db.add(event)
    _logger.info(
        json.dumps(
            {
                "event": "audit",
                "correlation_id": correlation_id,
                "actor": actor,
                "route": route,
                "reason_code": reason_code,
            }
        )
    )
    return event


def new_correlation_id() -> str:
    return secrets.token_hex(8)
