"""The integrated comparison run.

One command exercises every sink browserlessly against the vulnerable and half-fixed apps and
replays the identical request against the secure app, printing — per attack — the value
extracted and its source, the request, the acceptance decision, whose authority was used, the
resulting order and inventory state, the secure app's verdict, and the before/after comparison.

The headless-browser harness is the other driver: its browser tests assert that each vulnerable
client actually computes and sends the signature, verdict, digest, and pickup code, and that the
secure client sends none of them. Both drivers run under one `docker compose --profile verify`.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from dataclasses import dataclass

import httpx

from ..fixtures import CAPTURED_SUPERVISOR_DIGEST
from ..signing import DEMO_SIGNING_KEY, canonical_order_string, sign
from .cli import (
    enumerate_pickup_attack,
    forge_client_verdict_order,
    forge_embedded_key_order,
    login,
    replay_digest_attack,
)

SECURE_ACCOUNT = "tech-avery"
SECURE_PASSWORD = "avery-ninebark-demo"

Snapshot = tuple[list[tuple[str, str]], list[tuple[str, int]]]


@dataclass
class ComparisonRow:
    sink: str
    app: str
    driver: str
    extracted: str
    source: str
    request: str
    authority: str
    vulnerable_accepted: bool
    vulnerable_state: str | None
    secure_verdict: str
    secure_state_unchanged: bool

    def render(self) -> str:
        vuln = f"accepted={self.vulnerable_accepted} state={self.vulnerable_state}"
        return "\n".join([
            f"── {self.sink}  ·  {self.app}  ·  driver: {self.driver}",
            f"   extracted:        {self.extracted}",
            f"   from:             {self.source}",
            f"   request:          {self.request}",
            f"   authority used:   {self.authority}",
            f"   vulnerable app:   {vuln}",
            f"   secure app:       {self.secure_verdict}",
            f"   secure settled/inventory unchanged: {self.secure_state_unchanged}",
        ])


@dataclass
class Comparison:
    rows: list[ComparisonRow]

    @property
    def all_vulnerable_accepted(self) -> bool:
        return all(r.vulnerable_accepted for r in self.rows)

    @property
    def all_secure_unchanged(self) -> bool:
        return all(r.secure_state_unchanged for r in self.rows)

    def render(self) -> str:
        header = "keyjack — three-axis comparison (browserless driver; browser driver: the harness)"
        body = "\n\n".join(r.render() for r in self.rows)
        summary = (
            f"\nSUMMARY: every attack succeeded against the vulnerable/half-fixed apps "
            f"({self.all_vulnerable_accepted}); the secure app's settled state was unchanged "
            f"by every identical request ({self.all_secure_unchanged})."
        )
        return f"{header}\n\n{body}\n{summary}"


def _snapshot(client: httpx.Client, base_url: str) -> Snapshot:
    orders = client.get(f"{base_url}/api/orders").json()
    catalog = client.get(f"{base_url}/api/catalog").json()
    settled = sorted(
        (o["id"], o["state"]) for o in orders
        if o["state"] in {"auto_approved", "approved", "collected"}
    )
    stock = sorted((p["part_number"], p["stock"]) for p in catalog)
    return settled, stock


def _secure_order(client: httpx.Client, base_url: str, body: dict[str, object]) -> str:
    res = client.post(
        f"{base_url}/api/orders", json=body, headers={"X-Ninebark-Signature": "forged"}
    )
    return f"HTTP {res.status_code}, state={res.json().get('state')}" if res.status_code == 200 \
        else f"HTTP {res.status_code} (refused)"


def run_comparison(secure_url: str, vuln_url: str, halffixed_url: str) -> Comparison:
    rows: list[ComparisonRow] = []
    with httpx.Client(timeout=30.0) as secure:
        login(secure, secure_url, SECURE_ACCOUNT, SECURE_PASSWORD)

        # --- Sink 1: embedded signing key (vulnerable) -----------------------------------
        before = _snapshot(secure, secure_url)
        v = forge_embedded_key_order(vuln_url)
        verdict = _secure_order(secure, secure_url, {
            "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
            "unit_price_cents": 1, "restricted": False, "line_total_cents": 1,
        })
        rows.append(ComparisonRow(
            "embedded signing key", "vulnerable", "browserless", v.extracted_value,
            v.extracted_source, "forged price/restriction, valid signature",
            "tech-avery (forged facts)", v.order_state == "auto_approved", v.order_state,
            verdict, before == _snapshot(secure, secure_url),
        ))

        # --- Sink 2: client-computed verdict (vulnerable) --------------------------------
        before = _snapshot(secure, secure_url)
        v = forge_client_verdict_order(vuln_url)
        verdict = _secure_order(secure, secure_url, {
            "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
            "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
            "within_limit": True, "requires_supervisor": False,
        })
        rows.append(ComparisonRow(
            "client-computed verdict", "vulnerable", "browserless", v.extracted_value,
            v.extracted_source, "honest price, forged verdict", "tech-avery (forged verdict)",
            v.order_state == "auto_approved", v.order_state, verdict,
            before == _snapshot(secure, secure_url),
        ))

        # --- Sink 3: client-hashed credential (vulnerable) -------------------------------
        before = _snapshot(secure, secure_url)
        d = replay_digest_attack(vuln_url)
        secure_login = secure.post(
            f"{secure_url}/api/login",
            json={"account_id": "sup-navarro", "password": CAPTURED_SUPERVISOR_DIGEST},
        )
        rows.append(ComparisonRow(
            "client-hashed credential", "vulnerable", "browserless", d.extracted_value,
            d.extracted_source, "replay the captured supervisor digest",
            "sup-navarro (replayed digest)", d.order_state == "approved", d.order_state,
            f"HTTP {secure_login.status_code} (digest is a wrong password)",
            before == _snapshot(secure, secure_url),
        ))

        # --- Sink 4: weak pickup code (vulnerable) ---------------------------------------
        order_id, epoch = _seed_weak_pickup_target(vuln_url)
        before = _snapshot(secure, secure_url)
        e = enumerate_pickup_attack(vuln_url, order_id)
        secure_pickup = secure.post(
            f"{secure_url}/api/pickup", json={"code": f"PU-{epoch}-000"}
        )
        rows.append(ComparisonRow(
            "weak pickup code", "vulnerable", "browserless", e.accepted_code or "(none)",
            "disclosed created_at + 3 guessed digits",
            f"enumerated {e.candidate_count} candidates (bound {e.bound})",
            "tech-avery collecting tech-brooks's part", e.order_state == "collected",
            e.order_state, f"HTTP {secure_pickup.status_code} (no derived code accepted)",
            before == _snapshot(secure, secure_url),
        ))

        # --- Half-fixed variant: both attacks still land ---------------------------------
        half_attacks = [
            ("embedded signing key",
             forge_embedded_key_order(halffixed_url, from_config=True)),
            ("client-computed verdict",
             forge_client_verdict_order(halffixed_url, from_config=True)),
        ]
        for label, result in half_attacks:
            before = _snapshot(secure, secure_url)
            verdict = _secure_order(secure, secure_url, {
                "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1001",
                "unit_price_cents": 1, "restricted": False, "line_total_cents": 1,
            })
            rows.append(ComparisonRow(
                label, "half-fixed", "browserless", result.extracted_value,
                result.extracted_source, "key read from runtime config, forged body",
                "tech-avery (runtime key)", result.order_state == "auto_approved",
                result.order_state, verdict, before == _snapshot(secure, secure_url),
            ))

    return Comparison(rows)


def _seed_weak_pickup_target(vuln_url: str) -> tuple[str, int]:
    """Create tech-brooks's approved restricted order carrying a weak code, for enumeration."""

    from ..hashing import sha256_hex

    epoch = int(time.time())
    code = f"PU-{epoch}-042"
    order: dict[str, object] = {
        "part_number": "PN-7741", "quantity": 1, "work_order_id": "WO-1002",
        "unit_price_cents": 189_000, "restricted": True, "line_total_cents": 189_000,
        "within_limit": False, "requires_supervisor": True,
        "pickup_code": code, "created_at_epoch": epoch,
    }
    signature = sign(DEMO_SIGNING_KEY, canonical_order_string(
        part_number="PN-7741", quantity=1, work_order_id="WO-1002",
        unit_price_cents=189_000, restricted=True, line_total_cents=189_000,
        within_limit=False, requires_supervisor=True, pickup_code=code, created_at_epoch=epoch,
    ))
    with httpx.Client(timeout=15.0) as brooks:
        brooks.post(f"{vuln_url}/api/login",
                    json={"account_id": "tech-brooks",
                          "password_digest": sha256_hex("brooks-ninebark-demo")})
        order_id = brooks.post(
            f"{vuln_url}/api/orders", json=order,
            headers={"X-Ninebark-Signature": signature},
        ).json()["id"]
    with httpx.Client(timeout=15.0) as sup:
        sup.post(f"{vuln_url}/api/login",
                 json={"account_id": "sup-navarro",
                       "password_digest": sha256_hex("navarro-ninebark-demo")})
        sup.post(f"{vuln_url}/api/orders/{order_id}/approve")
    return order_id, epoch


def main(argv: Sequence[str] | None = None) -> int:
    secure_url = os.environ.get("KEYJACK_BASE_URL", "http://app:8000").rstrip("/")
    vuln_url = os.environ.get("KEYJACK_VULN_BASE_URL", "http://vulnerable-app:8000").rstrip("/")
    half_url = os.environ.get("KEYJACK_HALFFIXED_BASE_URL", "http://halffixed-app:8000").rstrip("/")
    comparison = run_comparison(secure_url, vuln_url, half_url)
    print(comparison.render())
    ok = comparison.all_vulnerable_accepted and comparison.all_secure_unchanged
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    import sys

    sys.exit(main())
