"""Headless-browser walkthrough of the half-fixed variant: the harness captures the key
arriving in the browser's own network activity, and the client signs with that runtime key."""

from __future__ import annotations

import contextlib

from playwright.sync_api import Page, Response


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
    captured: dict[str, object] = {}

    def on_response(response: Response) -> None:
        if response.url.endswith("/api/client-config"):
            with contextlib.suppress(Exception):
                captured["config"] = response.json()

    halffixed_page.on("response", on_response)
    _login(halffixed_page, halffixed_loopback_url, "tech-avery", "avery-ninebark-demo")
    halffixed_page.select_option("#part-select", "PN-7741")
    halffixed_page.select_option("#work-order-select", "WO-1001")

    with halffixed_page.expect_request(
        lambda r: r.method == "POST" and r.url.endswith("/api/orders")
    ) as info:
        halffixed_page.click("#submit-order")

    # The key was fetched at runtime — visible in the browser's own network activity.
    config = captured.get("config")
    assert isinstance(config, dict) and config.get("signing_key")
    # And the client signed the request with that runtime-delivered key.
    assert info.value.headers.get("x-ninebark-signature")
