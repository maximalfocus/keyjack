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


@pytest.fixture(scope="session")
def vuln_loopback_url() -> Iterator[str]:
    """A 127.0.0.1 forwarder to the vulnerable app.

    Driving the client over a loopback origin gives the browser a secure context — exactly
    what a human running the demo on 127.0.0.1 gets — so the client's WebCrypto signing works.
    """

    if not VULN_BASE_URL:
        pytest.skip("vulnerable app not enabled (KEYJACK_VULN_BASE_URL unset)")
    parsed = urlparse(VULN_BASE_URL)
    target = (parsed.hostname or "vulnerable-app", parsed.port or 8000)
    server = _ForwardServer(("127.0.0.1", 0), _forward_handler(target))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


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
