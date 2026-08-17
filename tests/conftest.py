"""Shared test fixtures.

Tests run inside the harness container and target the running secure application over the
internal demo network. Unit tests import the package directly and need no network.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import httpx
import pytest
from playwright.sync_api import Browser, Page, sync_playwright

BASE_URL = os.environ.get("KEYJACK_BASE_URL", "http://127.0.0.1:8000")


@pytest.fixture
def base_url() -> str:
    return BASE_URL


@pytest.fixture
def api() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=BASE_URL, timeout=15.0) as client:
        yield client


@pytest.fixture(scope="session")
def browser() -> Iterator[Browser]:
    with sync_playwright() as p:
        instance = p.chromium.launch(args=["--no-sandbox"])
        try:
            yield instance
        finally:
            instance.close()


@pytest.fixture
def page(browser: Browser) -> Iterator[Page]:
    context = browser.new_context(base_url=BASE_URL)
    pg = context.new_page()
    try:
        yield pg
    finally:
        context.close()
