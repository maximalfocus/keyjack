"""Headless-browser walkthrough of the vulnerable client: the key is readable in the served
source, and the client computes and sends the signature."""

from __future__ import annotations

from playwright.sync_api import Page


def _login(page: Page, base_url: str, account: str, password: str) -> None:
    page.goto(f"{base_url}/")
    page.wait_for_selector("#login-view:not([hidden])")
    page.fill("#account-id", account)
    page.fill("#password", password)
    page.click("#login-btn")
    page.wait_for_selector("#app-view:not([hidden])")
    page.wait_for_selector("#part-select option", state="attached")


def test_signing_key_is_readable_in_served_source(vuln_page: Page, vuln_base_url: str) -> None:
    source = vuln_page.request.get(f"{vuln_base_url}/static/app/client.js").text()
    # The key the server verifies against is delivered to the browser, in the clear.
    assert "SIGNING_KEY" in source
    assert "ninebark-demo-signing-key" in source


def test_client_hashes_the_password_before_login(
    vuln_page: Page, vuln_loopback_url: str
) -> None:
    # Driven over loopback for a secure context (WebCrypto), as a human on 127.0.0.1 would be.
    vuln_page.goto(f"{vuln_loopback_url}/")
    vuln_page.wait_for_selector("#login-view:not([hidden])")
    vuln_page.fill("#account-id", "tech-avery")
    vuln_page.fill("#password", "avery-ninebark-demo")
    with vuln_page.expect_request(
        lambda r: r.method == "POST" and r.url.endswith("/api/login")
    ) as info:
        vuln_page.click("#login-btn")
    body = info.value.post_data_json
    # The password never leaves as a password — only its SHA-256 digest does.
    assert "password" not in body
    assert len(body["password_digest"]) == 64


def test_client_computes_and_sends_a_signature(
    vuln_page: Page, vuln_loopback_url: str
) -> None:
    # Drive over loopback so the browser has a secure context for WebCrypto (as on 127.0.0.1).
    _login(vuln_page, vuln_loopback_url, "tech-avery", "avery-ninebark-demo")
    vuln_page.select_option("#part-select", "PN-1002")
    vuln_page.select_option("#work-order-select", "WO-1001")

    with vuln_page.expect_request(
        lambda r: r.method == "POST" and r.url.endswith("/api/orders")
    ) as info:
        vuln_page.click("#submit-order")

    request = info.value
    signature = request.headers.get("x-ninebark-signature")
    assert signature and len(signature) == 64  # hex SHA-256 HMAC computed in the browser

    vuln_page.wait_for_selector("#orders-table tbody tr")
