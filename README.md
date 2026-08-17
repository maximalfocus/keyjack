# keyjack

**Local-only educational material.** keyjack is a small, container-only demonstration of
*client-side crypto misuse* — the class of failure where a secret, a check, a credential, or a
source of randomness that is supposed to enforce a server's rules is instead placed in a browser
the user controls (OWASP **A02:2021**; CWE-320/321/798/602/836/338).

It models a fictional field-service parts-ordering application, **Ninebark Field Services**, and
shows the same lesson from several angles: *everything delivered to the browser is under the user's
control, so a secret you ship to the browser is published and a check you run in the browser is a
suggestion.*

Nothing here is deployed, hosted, or exposed beyond loopback; nothing contacts a real system; the
demo network has no egress; and every organisation, person, part, key, and credential is fictional
demonstration data.

## What is in this increment

This is the **secure baseline**: the reference application that does everything right, with **no
vulnerable code**. The server re-derives every security-relevant fact from state it holds — the
price and restriction from its own catalog, the authorization verdict from the authenticated actor's
server-held approval limit, the credential from a server-side KDF (Argon2id), and each pickup code
from a CSPRNG. The dependency-free browser client submits order *intent* only and keeps a purely
cosmetic "this needs supervisor approval" hint to prove a client-side check is a fine affordance and
a worthless control.

The intentionally vulnerable contrast, the browserless attacker CLI, and the full walkthrough are
delivered in later increments.

## Requirements

Only **Docker** (with the Compose plugin). No host Python, Node, or browser is needed — the
application, its tests, the linters, and the headless browser all run inside containers.

## Run it

```sh
# Verify everything (linters, type checks, unit + API + headless-browser tests) through the same
# container boundary that CI uses:
docker compose up --build --abort-on-container-exit --exit-code-from harness

# Explore the secure app by hand, then open http://127.0.0.1:8000
docker compose up --build app

# Tear everything down (removes ephemeral state):
docker compose down -v
```

Fresh deterministic state is seeded on every start. Demo accounts:

| Account | Role | Password |
|---|---|---|
| `tech-avery` | technician (limit $250.00) | `avery-ninebark-demo` |
| `tech-brooks` | technician (limit $250.00) | `brooks-ninebark-demo` |
| `sup-navarro` | supervisor | `navarro-ninebark-demo` |

## Layout

- `src/keyjack/` — the application package (`apps/secure.py` is the secure entry point).
- `src/keyjack/web/` — the readable, no-build client (templates and static assets).
- `harness/` — the Playwright / headless-Chromium verification image.
- `tests/` — unit, API, in-process, and browser tests.
- `compose.yaml` — the two-network stack: an internal, egress-free `demo` network for the app and
  harness, and an `edge` network used only to publish the app's loopback port.
