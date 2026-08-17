"""The intentionally vulnerable application (embedded signing key + client verdict).

This variant is local educational material only. It is absent from the default Compose path
and refuses to start unless **both** a non-default Compose profile and an explicit environment
acknowledgement are present.

Its client holds the signing key as a source constant, computes the authorization verdict, and
signs the whole body. The server verifies the signature correctly and then trusts the body — the
price, the restriction, and the posted verdict. The failure is key placement, not verification.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from ..config import Settings, load_settings
from .bodytrusting import register_body_trusting_order_route
from .common import (
    build_app,
    register_auth,
    register_pages,
    register_reads,
    register_workflow,
)

ACK_ENV = "KEYJACK_ACK_VULNERABLE"
REQUIRED_ACK = "i-understand-this-is-intentionally-vulnerable"


def require_optin() -> None:
    """Refuse to start without the explicit acknowledgement (one of the two opt-in gates)."""

    if os.environ.get(ACK_ENV, "") != REQUIRED_ACK:
        raise RuntimeError(
            "Refusing to start intentionally vulnerable material. Set "
            f"{ACK_ENV}={REQUIRED_ACK} and select a non-default Compose profile to run this "
            "local educational material."
        )


def create_vulnerable_app(settings: Settings | None = None) -> FastAPI:
    require_optin()
    settings = settings or load_settings()
    app, rt = build_app("keyjack (VULNERABLE)", settings, "vulnerable")
    register_pages(app, rt, vulnerable=True, client_src="/static/app/client.js")
    register_auth(app, rt, digest=True)  # the client-hashed credential sink
    register_reads(app, rt)
    register_workflow(app, rt, enforce_pickup_owner=False)  # the weak-pickup sink
    register_body_trusting_order_route(app, rt)
    return app
