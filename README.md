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

**The secure baseline.** The reference application that does everything right: the server re-derives
every security-relevant fact from state it holds — the price and restriction from its own catalog, the
authorization verdict from the authenticated actor's server-held approval limit, the credential from a
server-side KDF (Argon2id), and each pickup code from a CSPRNG. The dependency-free browser client
submits order *intent* only and keeps a purely cosmetic "this needs supervisor approval" hint to prove
a client-side check is a fine affordance and a worthless control.

**Vulnerable contrasts (opt-in).** A vulnerable variant that delegates four decisions to a browser
the attacker owns:

- an **embedded HMAC key** the client signs order bodies with — the server verifies correctly and is
  defeated anyway, because the key is shipped to every browser;
- a **client-computed verdict** (`within_limit` / `requires_supervisor`) the server routes on;
- a **client-hashed credential** — the client posts `SHA-256(password)` "so the password never
  leaves the device", so the digest *is* the credential and a captured digest authenticates; and
- a **weak pickup code** the client mints as `PU-<created_at>-<three Math.random() digits>`, which
  the shared order queue discloses enough of to enumerate a fixed ≤1,000-candidate window.

Each one converges on the same outcome: a restricted, over-limit part obtained with no supervisor
decision.

**The half-fixed variant.** Applies every plausible remediation — server-side verification retained,
the key removed from the source file and served from `/api/client-config` at runtime, the client
minified, the verdict itself signed — and falls anyway, because the key still reaches the client, now
over the wire. The harness reads it straight out of the browser's network activity; the CLI reads it
from the same response.

Against the secure app every one of these requests changes nothing.

**The full walkthrough** — the four sinks, the converging outcome, the half-fixed variant, each fix,
the terminology, the bounded-enumeration boundary, and the legitimate-client-side-crypto dividing
line — is in [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md). One command prints the whole three-axis
comparison (every sink × the three apps × the secure contrast):

```sh
KEYJACK_ACK_VULNERABLE=i-understand-this-is-intentionally-vulnerable \
  docker compose --profile verify run --rm harness keyjack-compare
```

## Requirements

Only **Docker** (with the Compose plugin). No host Python, Node, or browser is needed — the
application, its tests, the linters, and the headless browser all run inside containers.

## Run it

```sh
# Explore the SECURE app by hand, then open http://127.0.0.1:8000
docker compose up --build app

# Full verification (linters, type checks, unit + API + CLI + headless-browser tests) across the
# secure AND the opt-in vulnerable app — the same boundary CI uses. Two deliberate opt-ins are
# required to bring the vulnerable app up: the non-default `verify` profile and the acknowledgement.
KEYJACK_ACK_VULNERABLE=i-understand-this-is-intentionally-vulnerable \
  docker compose --profile verify up --build --abort-on-container-exit --exit-code-from harness

# Explore the intentionally VULNERABLE app (same two opt-ins), then open http://127.0.0.1:8001
KEYJACK_ACK_VULNERABLE=i-understand-this-is-intentionally-vulnerable \
  docker compose --profile vulnerable up --build vulnerable-app

# Tear everything down (removes ephemeral state):
docker compose --profile verify down -v
```

The vulnerable app is **absent from the default `docker compose up`** and refuses to start unless
**both** the non-default profile and the `KEYJACK_ACK_VULNERABLE` acknowledgement are present.

### Browserless attacker CLI

The `keyjack-attack` tool reproduces each attack over plain HTTP, with no browser — the proof that the
client was never a boundary. Each subcommand reads the key it needs, forges a signed order for the
restricted part, submits it, and prints the key's source, the request, the response, and the state.

```sh
# against the vulnerable app (http://127.0.0.1:8001):
keyjack-attack --base-url http://127.0.0.1:8001 embedded-key                 # forge price/restriction
keyjack-attack --base-url http://127.0.0.1:8001 client-verdict               # forge the verdict
keyjack-attack --base-url http://127.0.0.1:8001 replay-digest                # replay the supervisor digest
keyjack-attack --base-url http://127.0.0.1:8001 enumerate-pickup --order ORD-… # guess a weak code

# against the half-fixed app (http://127.0.0.1:8002): the key is read from its runtime config
keyjack-attack --base-url http://127.0.0.1:8002 half-fixed
```

The `enumerate-pickup` subcommand tries a fixed window of at most 1,000 codes derived from the
disclosed timestamp and prints its candidate count and bound. There is no wordlist, no
general-purpose brute-force tool, and no `Math.random()` state-recovery code anywhere in the repo.

Fresh deterministic state is seeded on every start. Demo accounts:

| Account | Role | Password |
|---|---|---|
| `tech-avery` | technician (limit $250.00) | `avery-ninebark-demo` |
| `tech-brooks` | technician (limit $250.00) | `brooks-ninebark-demo` |
| `sup-navarro` | supervisor | `navarro-ninebark-demo` |

## Layout

- `src/keyjack/` — the application package (`apps/secure.py`, `apps/vulnerable.py`, and
  `apps/halffixed.py` are the entry points; `apps/common.py` holds the shared model, auth, read
  surface, and workflow; `apps/bodytrusting.py` is the shared vulnerable order route).
- `src/keyjack/signing.py` — the HMAC canonicalization and verification for the vulnerable contrast.
- `src/keyjack/attacker/` — the browserless attacker CLI (`keyjack-attack`).
- `src/keyjack/web/` — the readable, no-build clients (templates and static assets).
- `harness/` — the Playwright / headless-Chromium verification image.
- `tests/` — unit, API, in-process, browser, opt-in-gate, and containment tests.
- `compose.yaml` — the two-network stack: an internal, egress-free `demo` network for the apps and
  harness, and an `edge` network used only to publish loopback ports for manual exploration.

## Boundaries

keyjack is a teaching demonstration, not a product. It is not deployed, hosted, or exposed beyond
loopback; it ships no package, image, or public endpoint; and it makes no hosting or production claim.
There is no support SLA, no guaranteed response time, and no long-term compatibility commitment. The
`vulnerable` and `half-fixed` applications are intentionally exploitable and gated behind two
deliberate opt-in actions — see [`SECURITY.md`](SECURITY.md).

## License & contributing

MIT — see [`LICENSE`](LICENSE). Contributions welcome within the project's scope; see
[`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).
