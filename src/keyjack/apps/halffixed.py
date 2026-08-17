"""The half-fixed variant.

It applies every plausible remediation and falls anyway:

- server-side signature verification is retained (it was always correct);
- the key is removed from the client source file and served from ``/api/client-config`` at
  request time;
- the client bundle is minified;
- the authorization verdict is itself signed with that key.

None of it helps, because the key is still delivered to the client — now over the wire, where
the harness (and the browserless CLI) simply read it out of the network response. It reuses the
same body-trusting order route as the vulnerable app.
"""

from __future__ import annotations

from fastapi import FastAPI

from ..config import Settings, load_settings
from ..signing import DEMO_SIGNING_KEY
from .bodytrusting import register_body_trusting_order_route
from .common import (
    build_app,
    register_auth,
    register_pages,
    register_reads,
    register_workflow,
)
from .vulnerable import require_optin


def create_halffixed_app(settings: Settings | None = None) -> FastAPI:
    require_optin()
    settings = settings or load_settings()
    app, rt = build_app("keyjack (HALF-FIXED)", settings, "halffixed")
    register_pages(
        app,
        rt,
        vulnerable=True,
        client_src="/static/app/client.min.js",
        client_config_key=DEMO_SIGNING_KEY,  # "removed from source", served at runtime
    )
    register_auth(app, rt)
    register_reads(app, rt)
    register_workflow(app, rt)
    register_body_trusting_order_route(app, rt)
    return app
