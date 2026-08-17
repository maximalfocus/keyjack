"""The vulnerable app refuses to start without the explicit acknowledgement env var.

This is one of the two deliberate opt-in gates; the other (a non-default Compose profile) is
enforced by the stack definition and exercised by the full verification run.
"""

from __future__ import annotations

import pytest

from keyjack.apps.vulnerable import ACK_ENV, REQUIRED_ACK, create_vulnerable_app
from keyjack.config import Settings


def _fast_settings(tmp_path: object) -> Settings:
    return Settings(
        db_url=f"sqlite+pysqlite:///{tmp_path}/kj.db",  # type: ignore[str-bytes-safe]
        argon2_time_cost=1, argon2_memory_cost_kib=8 * 1024, argon2_parallelism=1,
    )


def test_refuses_without_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    monkeypatch.delenv(ACK_ENV, raising=False)
    with pytest.raises(RuntimeError):
        create_vulnerable_app(_fast_settings(tmp_path))


def test_refuses_with_wrong_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    monkeypatch.setenv(ACK_ENV, "sure-whatever")
    with pytest.raises(RuntimeError):
        create_vulnerable_app(_fast_settings(tmp_path))


def test_starts_with_correct_acknowledgement(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    monkeypatch.setenv(ACK_ENV, REQUIRED_ACK)
    app = create_vulnerable_app(_fast_settings(tmp_path))
    assert app is not None
