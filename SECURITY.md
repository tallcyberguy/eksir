# Security Policy

EKSIR is a security operations platform. It is deployed inside SOC environments,
it holds credentials for connected EDR/XDR tenants, and it processes untrusted
alert and webhook payloads. Because of that, we treat vulnerability reports with
priority and ask that you disclose them responsibly.

## Supported versions

Security fixes land on the latest release line. Older lines are not backported.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

Pre-1.0 releases move fast: run a recent 0.2.x build and rebuild the backend and
worker images after pulling fixes (backend source is baked into the image, not
host-mounted).

## Reporting a vulnerability

**Do NOT open a public GitHub issue, pull request, or Discussion for a security
vulnerability.** Public disclosure before a fix is available puts every deployment
at risk.

Report privately through one of these channels:

1. **GitHub Private Vulnerability Reporting (preferred).** Go to the repository's
   **Security** tab and choose **Report a vulnerability**. This opens a private
   advisory visible only to you and the maintainers, and it keeps the report,
   the discussion, and the eventual advisory in one place.
2. **Email fallback.** If you cannot use GitHub advisories, email
   **hello@eksir.com** with the subject line prefixed `SECURITY:`. Encrypt or
   request a secure channel if the details are sensitive.

Please include, where you can:

- A description of the issue and the impact you believe it has.
- The affected component (for example a `routes/` endpoint, the webhook ingest,
  a connector/adapter, the LLM tool path, or the deploy stack).
- Version or commit SHA, and the deployment shape (docker compose profile, LLM
  backend, whether EDR connectors are enabled).
- Step-by-step reproduction, a proof of concept, or logs. Redact any real
  customer data before sending.

## What to expect

- **Acknowledgement within 3 business days** confirming we received the report.
- An initial assessment and a severity call shortly after triage.
- Regular updates while we work on a fix, and credit in the advisory and release
  notes if you would like it (let us know your preference).

## Coordinated disclosure

We follow coordinated disclosure. We ask that you give us a reasonable window to
investigate and ship a fix before any public disclosure. We will agree a
disclosure date with you, publish a GitHub Security Advisory (and a CVE where
warranted) once a fix is available, and note the fix in
[`CHANGELOG.md`](./CHANGELOG.md). We will not pursue legal action against
researchers who act in good faith, avoid privacy violations and service
disruption, and give us a chance to respond before going public.

## Known design tradeoffs

Some accepted risks are documented in the repository so they are not mistaken for
undiscovered bugs. Before reporting, please check whether the behavior is already
a captured tradeoff, for example
[`docs/WEBHOOK-SECURITY-NOTE.md`](./docs/WEBHOOK-SECURITY-NOTE.md), which explains
why webhook HMAC secrets are stored in a recoverable form and the mitigations in
place. A report that a documented tradeoff could be hardened further is still
welcome; a report that treats it as an unknown flaw is duplicate.

## Scope

In scope: the code in this repository (backend orchestrator and worker, frontend,
connectors/adapters, deploy configuration, and the landing site under `landing/`).

Out of scope: vulnerabilities in third-party services reached over the network
(Anthropic, OpenAI, Trend Micro Vision One, Microsoft Defender/Graph, VirusTotal,
AbuseIPDB, OTX, abuse.ch, IPinfo), in the REMnux base image, or in upstream
dependencies. Report those to their respective maintainers. If a dependency issue
is exploitable specifically because of how EKSIR uses it, we do want to hear about
that path.
