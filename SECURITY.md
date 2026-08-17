# Security policy

keyjack is **intentionally vulnerable local educational material**. Please read this before reporting
anything.

## The intentional flaws are the point

The `vulnerable` and `half-fixed` applications are *designed* to be exploitable. They ship an embedded
signing key, trust a client-computed authorization verdict, compare a client-computed password digest,
and mint a guessable pickup code — on purpose, to demonstrate client-side crypto misuse (OWASP
A02:2021). These are **not** vulnerabilities to report. They are gated behind two deliberate opt-in
actions (a non-default Compose profile **and** an explicit acknowledgement environment variable) and
are meant to run only on loopback.

The `secure` application is the reference for how the same product should behave. If you believe the
**secure** application can be made to auto-approve a restricted part, accept a wrong credential, or
release a part without a valid server-issued code — that would be an unintended flaw worth reporting.

## Reporting an unintended flaw

Report unintended security issues privately through **GitHub's private vulnerability reporting** on
this repository (the *Security → Report a vulnerability* tab). Please do not open a public issue for a
suspected unintended flaw.

When reporting, include the exact commands, the application variant (`secure`, `vulnerable`, or
`half-fixed`), and the observed versus expected behavior.

## Scope and boundaries

- Everything here runs locally on a hermetic container network with no egress. There is no hosted
  endpoint, deployed service, or published package or image to attack.
- All organizations, people, parts, keys, digests, and codes are conspicuously fictional demonstration
  data. No real credential, key, or personal information is accepted, stored, or logged.
- This project offers no support SLA, no guaranteed response time, and no long-term compatibility
  commitment.
