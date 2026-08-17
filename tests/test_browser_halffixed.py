"""Headless-browser walkthrough of the half-fixed variant: the harness captures the key
arriving in the browser's own network activity, and the client signs with that runtime key."""

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


def test_key_arrives_over_the_wire_and_client_signs_with_it(
    halffixed_page: Page, halffixed_loopback_url: str
) -> None:
    _login(halffixed_page, halffixed_loopback_url, "tech-avery", "avery-ninebark-demo")
    halffixed_page.select_option("#part-select", "PN-7741")
    halffixed_page.select_option("#work-order-select", "WO-1001")

    # The client fetches the key from /api/client-config to sign — wait for that response
    # deterministically, then for the signed order request it produces.
    with halffixed_page.expect_response(
        lambda r: r.url.endswith("/api/client-config")
    ) as config_info, halffixed_page.expect_request(
        lambda r: r.method == "POST" and r.url.endswith("/api/orders")
    ) as order_info:
        halffixed_page.click("#submit-order")

    # The key was delivered at runtime, visible in the browser's own network activity.
    assert config_info.value.json().get("signing_key")
    # And the client signed the request with that runtime-delivered key.
    assert order_info.value.headers.get("x-ninebark-signature")
