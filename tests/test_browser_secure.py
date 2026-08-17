"""Headless-browser tests: assertions that only a real browser driving the client can make."""

from __future__ import annotations

import re

from playwright.sync_api import Page, expect

DEMO_PASSWORDS = {
    "tech-avery": "avery-ninebark-demo",
    "sup-navarro": "navarro-ninebark-demo",
}

# Actual client-crypto invocations a secure client must never make (matched as code, not
# prose, so a readable comment that merely names them cannot appear either).
FORBIDDEN_CLIENT_MARKERS = ["crypto.subtle", "Math.random", "new TextEncoder"]

# A high-entropy string literal would betray an embedded key or secret.
SECRET_LITERAL = re.compile(r"""['"][A-Za-z0-9+/=_-]{40,}['"]""")


def _login(page: Page, base_url: str, account_id: str) -> None:
    page.goto(f"{base_url}/")
    page.wait_for_selector("#login-view:not([hidden])")
    page.fill("#account-id", account_id)
    page.fill("#password", DEMO_PASSWORDS[account_id])
    page.click("#login-btn")
    page.wait_for_selector("#app-view:not([hidden])")
    # <option> elements are never "visible" to Playwright; wait for DOM attachment instead.
    page.wait_for_selector("#part-select option", state="attached")


def test_served_client_ships_no_key_or_client_crypto(page: Page, base_url: str) -> None:
    source = page.request.get(f"{base_url}/static/app/client.js").text()
    for marker in FORBIDDEN_CLIENT_MARKERS:
        assert marker not in source, f"secure client must not contain {marker!r}"
    assert SECRET_LITERAL.search(source) is None, "secure client must ship no secret literal"


def test_ux_hint_renders_for_restricted_and_unrestricted(page: Page, base_url: str) -> None:
    _login(page, base_url, "tech-avery")

    page.select_option("#part-select", "PN-7741")  # restricted, over limit
    expect(page.locator("#order-hint")).to_contain_text("supervisor approval")

    page.select_option("#part-select", "PN-1002")  # cheap, unrestricted
    expect(page.locator("#order-hint")).to_contain_text("auto-approved")


def test_client_submits_intent_only(page: Page, base_url: str) -> None:
    _login(page, base_url, "tech-avery")
    page.select_option("#part-select", "PN-7741")
    page.select_option("#work-order-select", "WO-1001")

    with page.expect_request(
        lambda r: r.method == "POST" and r.url.endswith("/api/orders")
    ) as info:
        page.click("#submit-order")

    body = info.value.post_data_json
    # The client sends only order intent — no price, no verdict, no signature.
    assert set(body.keys()) == {"part_number", "quantity", "work_order_id"}

    # And the server still routes the restricted part to supervisor review.
    expect(page.locator("#orders-table tbody")).to_contain_text("pending_supervisor")


def test_ux_hint_is_not_a_control(page: Page, base_url: str) -> None:
    # The hint says "auto-approved" for a cheap part, but the *server* decides regardless.
    _login(page, base_url, "tech-avery")
    page.select_option("#part-select", "PN-5533")  # restricted but under limit
    expect(page.locator("#order-hint")).to_contain_text("supervisor approval")
    page.select_option("#work-order-select", "WO-1001")
    page.click("#submit-order")
    expect(page.locator("#orders-table tbody")).to_contain_text("pending_supervisor")
