# Contributing

Thanks for your interest. keyjack is a small, self-contained **educational** demonstration, not a
product; contributions that keep it clear, correct, and safe are welcome.

## What fits

- Fixes to the secure application, the readable clients, the harness, the CLI, or the documentation.
- Improvements that make a lesson clearer without changing the observable behavior or the safety
  boundary.

## What does not fit

- Any general-purpose brute-force tool, wordlist, password cracker, or `Math.random()` state-recovery
  implementation. The one enumeration is deliberately bounded to a fixed, documented ≤1,000-candidate
  structural window against the demo's own container.
- Interaction with, or testing against, any real application, site, vendor, or third-party system.
- Anything that deploys, hosts, or exposes a component beyond loopback, or that adds a real credential,
  key, or personal identifier. All demonstration data must stay conspicuously fictional.

## Running the checks

You need only **Docker** (with the Compose plugin). Everything — the application, its tests, the
linters, and the headless browser — runs inside containers. Run the same boundary CI uses:

```sh
KEYJACK_ACK_VULNERABLE=i-understand-this-is-intentionally-vulnerable \
  docker compose --profile verify up --build --abort-on-container-exit --exit-code-from harness
```

This runs Ruff, mypy, and the unit, API, in-process, browser, and comparison tests across the secure,
vulnerable, and half-fixed applications. Please make sure it is green before opening a pull request.

## Reporting security issues

The vulnerable and half-fixed applications are intentionally exploitable — see
[`SECURITY.md`](SECURITY.md) for what is and is not worth reporting, and the private reporting path for
unintended flaws.
