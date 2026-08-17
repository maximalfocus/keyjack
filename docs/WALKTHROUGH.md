# keyjack — walkthrough

> **Local-only educational material.** Everything here is fictional and runs on a hermetic
> container network with no egress. The vulnerable and half-fixed applications are *intentionally
> vulnerable* and must never be deployed or exposed beyond loopback.

## The one sentence

**Everything delivered to the browser is under the user's control.** A secret you ship to the
browser is published, and a check you run in the browser is a suggestion. keyjack shows this four
different ways, all converging on one outcome: a restricted, over-limit part — a `PN-7741` thermal
imaging module — obtained by a technician no supervisor ever approved.

## The cast (all fictional)

**Ninebark Field Services** lets technicians order parts against work orders; supervisors approve
what technicians may not self-approve. The server's rules are the only rules that matter:

- every technician has a **server-held** approval limit (`tech-avery`: $250.00);
- an order at or under the limit for an unrestricted part is auto-approved; anything else is
  `pending_supervisor`;
- some parts are **restricted** regardless of price (`PN-7741`, $1,890.00; `PN-5533`, $220.00 —
  restricted while *under* the limit, so price and restriction are visibly independent);
- an approved order is collected from the parts desk with a **pickup code**.

The attacker is `tech-avery`, a legitimately registered technician — the lowest-privilege insider.
The victims, `sup-navarro` (a supervisor) and `tech-brooks` (a peer), do nothing but their jobs.

## Terminology, in plain language

The umbrella term is **client-side crypto misuse** (a.k.a. *client-side enforcement of server-side
security*, *client-side trust*, *shipped cryptographic key*) — OWASP **A02:2021 Cryptographic
Failures**:

| Code | Name | In plain words |
|---|---|---|
| **CWE-320** | Key management errors | The key is in the wrong place — the browser. |
| **CWE-321 / CWE-798** | Hard-coded / shipped key | A key delivered to the client is not a secret. |
| **CWE-602** | Client-side enforcement of server-side security | A check the browser runs is advice, not a control. |
| **CWE-836** | Use of password hash instead of password | A digest the client posts *is* the credential. |
| **CWE-338 / CWE-330** | Weak PRNG / insufficient randomness | `Math.random()` is not a source of security values. |

## The four sinks

Run the vulnerable app (two deliberate opt-ins) and reproduce each attack with the browserless CLI:

```sh
KEYJACK_ACK_VULNERABLE=i-understand-this-is-intentionally-vulnerable \
  docker compose --profile vulnerable up --build vulnerable-app   # http://127.0.0.1:8001
```

### 1. Embedded signing key — *correct crypto still fails*

The vulnerable client holds an HMAC key as a source constant and signs the order body with WebCrypto.
The server verifies that signature **correctly** — canonical serialization, constant-time compare, a
tampered body with a stale signature rejected — and then trusts the signed `unit_price_cents` and
`restricted`. Because the key is delivered to every browser, anyone can sign false facts:

```sh
keyjack-attack --base-url http://127.0.0.1:8001 embedded-key
```

A restricted $1,890 part, signed as a $0.01 unrestricted one, is **auto-approved**. This is *not* a
verification bug: *"we sign our API requests"* is an integrity mechanism only when the signer's key is
not also the attacker's.

### 2. Client-computed verdict — *a check in the browser is a suggestion*

The vulnerable client computes `within_limit` / `requires_supervisor` and posts them; the server
routes on the submitted verdict. Flip them and a genuinely restricted, over-limit order is approved:

```sh
keyjack-attack --base-url http://127.0.0.1:8001 client-verdict
```

### 3. Client-hashed credential — *the digest is the credential*

The vulnerable client computes `SHA-256(password)` "so the password never leaves this device" and
posts the digest; the server compares it to the stored digest. Hashing in the browser **relocates**
the credential rather than protecting it (CWE-836): a captured digest authenticates, and the server
loses the ability to apply a slow, salted key-derivation function. A checked-in fictional digest for
`sup-navarro` is replayed to approve the attacker's own order — no password known:

```sh
keyjack-attack --base-url http://127.0.0.1:8001 replay-digest
```

### 4. Weak pickup code — *`Math.random()` is not security randomness*

The vulnerable client mints `PU-<created_at epoch>-<three digits from Math.random()>`. The shared
order queue discloses `created_at` to the second, so "6 characters and unpredictable" collapses to a
fixed window of at most **1,000** candidates:

```sh
keyjack-attack --base-url http://127.0.0.1:8001 enumerate-pickup --order ORD-…
```

One enumerated code releases `tech-brooks`'s approved restricted part to `tech-avery`. The run prints
its candidate count and its ≤1,000 bound.

## The half-fixed variant — *obfuscation is not secrecy*

The half-fixed app (`http://127.0.0.1:8002`) applies every plausible fix and falls anyway: server-side
verification retained, the key **removed from the source file** and served from `/api/client-config`
at runtime, the bundle **minified**, and the verdict itself **signed**. All of it is defeated by the
same one-line observation — the key is still delivered to the client, now over the wire:

```sh
keyjack-attack --base-url http://127.0.0.1:8002 half-fixed
```

The harness reads the key straight out of the browser's network activity; the CLI reads it from the
same response. Minifying and moving a secret to runtime delivery hides it from a casual reader, not
from anyone who opens the network tab.

## The fix — *re-derive every security-relevant fact server-side*

The secure app (the default, `http://127.0.0.1:8000`) does everything right:

- **price and restriction** from its own catalog — the request's fields are ignored;
- **authorization** recomputed from the authenticated actor's server-held limit and the catalog flag
  (the secure client *keeps* its identical limit check as a UX hint, proving the client check was
  never the sin);
- **the credential** verified against a modern salted KDF (Argon2id), storing only its output — a
  submitted value is always a claim to verify, never a proof;
- **the pickup code** generated by a CSPRNG (≥256 bits), bound to the order and its owner, single-use
  and expiring.

Against the secure app, every attack above changes nothing: the forged signature is meaningless
because no client holds a key, the smuggled verdict is ignored (not rejected loudly — no field
oracle), the replayed digest is an ordinary wrong password, and no derived pickup code is ever
accepted. See it all at once:

```sh
KEYJACK_ACK_VULNERABLE=i-understand-this-is-intentionally-vulnerable \
  docker compose --profile verify run --rm harness keyjack-compare
```

## The dividing line — legitimate client-side cryptography

Client-side cryptography is not the villain. End-to-end encryption is client-side crypto done right:
the server is *deliberately excluded* and the user holds their own key. The dividing line is simple —
**client-side crypto can protect the user *from the server*, never the server *from the user*.** Every
sink here misuses it in the second direction.

## The boundary — no cracking, no predictor

The one guessing mechanism is bounded to a fixed, documented **≤1,000-candidate** window derived
structurally from a timestamp the demo's own API returns, run only against the demo's own container.
The repository ships **no** wordlist, **no** general-purpose brute-force tool, and **no**
`Math.random()` state-recovery implementation. Real `Math.random()` output is predictable by
engine-state recovery; keyjack deliberately proves the weakness structurally instead of shipping a
predictor. Nothing is cracked — the captured digest is a checked-in fictional fixture.

## Distinctions from adjacent demonstrations

- **`traceheist`** (A02) is about client-side crypto whose *key scope and session binding* are wrong;
  keyjack is about a key or a check being *on the client at all*, with otherwise textbook-correct
  cryptography.
- **`claimjumper`** (API2 · A07) is about a server that *verifies wrongly* (`alg:none`, ignored
  expiry, a weak secret); keyjack's server verifies *correctly* and is defeated because the key was
  published to every browser.
- **`roleless`** (API5) reads a role from a client-supplied header; keyjack's client verdict arrives
  *signed*, and the fix is server-side recomputation rather than a router policy table.
- **`fieldblind`** (API3) binds every submitted property on an owned object; keyjack's server accepts
  a *signed* body's price and authorization fields, and the control is re-deriving those facts from
  server-held state rather than a per-actor schema.
