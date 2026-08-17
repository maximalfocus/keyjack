"""The verification network is hermetic: from inside the demo network, no external host is
reachable. Runs only inside the Compose demo network (where the marker env is set)."""

from __future__ import annotations

import os

import httpx
import pytest

IN_DEMO_NET = os.environ.get("KEYJACK_IN_DEMO_NET") == "1"


@pytest.mark.skipif(not IN_DEMO_NET, reason="only meaningful inside the internal demo network")
def test_demo_network_has_no_egress() -> None:
    with pytest.raises(httpx.HTTPError):
        httpx.get("http://example.com", timeout=4.0)
    with pytest.raises(httpx.HTTPError):
        httpx.get("https://api.github.com", timeout=4.0)
