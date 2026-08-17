"""The browserless attacker CLI reproduces the forgery with no browser at all."""

from __future__ import annotations

from keyjack.attacker.cli import forge_client_verdict_order, forge_embedded_key_order
from keyjack.signing import DEMO_SIGNING_KEY


def test_cli_forges_with_extracted_key(vuln_base_url: str) -> None:
    result = forge_embedded_key_order(vuln_base_url)

    # The key was read straight out of the served client source.
    assert result.extracted_value == DEMO_SIGNING_KEY
    assert result.extracted_source.endswith("/static/app/client.js")

    # The forged, validly-signed order for the restricted part was auto-approved.
    assert result.response_status == 200
    assert result.order_state == "auto_approved"

    rendered = result.render()
    assert "embedded-signing-key" in rendered
    assert "auto_approved" in rendered


def test_cli_forges_the_client_verdict(vuln_base_url: str) -> None:
    result = forge_client_verdict_order(vuln_base_url)
    # Honest restricted price, but a forged verdict the server trusted.
    assert result.order_state == "auto_approved"
    assert result.extracted_source.endswith("/static/app/client.js")
    assert result.sink == "client-verdict"
