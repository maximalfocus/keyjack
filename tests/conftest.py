"""Shared test fixtures.

Tests run inside the harness container and target the running secure application over the
internal demo network. Unit tests import the package directly and need no network.
"""

from __future__ import annotations

import contextlib
import os
import socket
import socketserver
import threading
from collections.abc import Iterator
from urllib.parse import urlparse

import httpx
import pytest
from playwright.sync_api import Browser, Page, sync_playwright

BASE_URL = os.environ.get("KEYJACK_BASE_URL", "http://127.0.0.1:8000")
VULN_BASE_URL = os.environ.get("KEYJACK_VULN_BASE_URL", "")
HALFFIXED_BASE_URL = os.environ.get("KEYJACK_HALFFIXED_BASE_URL", "")


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            dst.shutdown(socket.SHUT_WR)


class _ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _forward_handler(target: tuple[str, int]) -> type[socketserver.BaseRequestHandler]:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            with socket.create_connection(target) as upstream:
                worker = threading.Thread(
                    target=_pipe, args=(self.request, upstream), daemon=True
                )
                worker.start()
                _pipe(upstream, self.request)
                worker.join(timeout=2)

    return Handler


def _loopback_forwarder(base_url: str, missing_msg: str) -> Iterator[str]:
    """Yield a 127.0.0.1 URL forwarding to ``base_url``.

    Driving the client over a loopback origin gives the browser a secure context — exactly
    what a human running the demo on 127.0.0.1 gets — so the client's WebCrypto signing works.
    """

    if not base_url:
        pytest.skip(missing_msg)
    parsed = urlparse(base_url)
    target = (parsed.hostname or "localhost", parsed.port or 8000)
    server = _ForwardServer(("127.0.0.1", 0), _forward_handler(target))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def vuln_loopback_url() -> Iterator[str]:
    yield from _loopback_forwarder(VULN_BASE_URL, "vulnerable app not enabled")


@pytest.fixture(scope="session")
def halffixed_loopback_url() -> Iterator[str]:
    yield from _loopback_forwarder(HALFFIXED_BASE_URL, "half-fixed app not enabled")


@pytest.fixture
def base_url() -> str:
    return BASE_URL


@pytest.fixture
def api() -> Iterator[httpx.Client]:
    with httpx.Client(base_url=BASE_URL, timeout=15.0) as client:
        yield client


@pytest.fixture
def vuln_base_url() -> str:
    """Base URL of the opt-in vulnerable app, or skip when it is not enabled/reachable."""

    if not VULN_BASE_URL:
        pytest.skip("vulnerable app not enabled (KEYJACK_VULN_BASE_URL unset)")
    try:
        httpx.get(f"{VULN_BASE_URL}/health", timeout=5.0)
    except httpx.HTTPError:
        pytest.skip("vulnerable app not reachable")
    return VULN_BASE_URL


@pytest.fixture
def vuln_api(vuln_base_url: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=vuln_base_url, timeout=15.0) as client:
        yield client


@pytest.fixture
def vuln_page(browser: Browser, vuln_base_url: str) -> Iterator[Page]:
    context = browser.new_context(base_url=vuln_base_url)
    pg = context.new_page()
    try:
        yield pg
    finally:
        context.close()


@pytest.fixture
def halffixed_base_url() -> str:
    if not HALFFIXED_BASE_URL:
        pytest.skip("half-fixed app not enabled (KEYJACK_HALFFIXED_BASE_URL unset)")
    try:
        httpx.get(f"{HALFFIXED_BASE_URL}/health", timeout=5.0)
    except httpx.HTTPError:
        pytest.skip("half-fixed app not reachable")
    return HALFFIXED_BASE_URL


@pytest.fixture
def halffixed_api(halffixed_base_url: str) -> Iterator[httpx.Client]:
    with httpx.Client(base_url=halffixed_base_url, timeout=15.0) as client:
        yield client


@pytest.fixture
def halffixed_page(browser: Browser, halffixed_base_url: str) -> Iterator[Page]:
    context = browser.new_context(base_url=halffixed_base_url)
    pg = context.new_page()
    try:
        yield pg
    finally:
        context.close()


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
