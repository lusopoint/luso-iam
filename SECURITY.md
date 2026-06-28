# Security Policy

Thank you for helping keep this project and its users safe. As an identity and access management server, security issues here can have outsized impact, and we take reports seriously.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.** Public disclosure before a fix is available puts every deployment at risk.

Instead, report privately through GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the advisory form with the details below.

This opens a private channel visible only to you and the maintainers, and lets us collaborate on a fix and a coordinated disclosure.

If you are unable to use GitHub's private reporting for some reason, open a regular issue that contains **only** a request for a private contact channel, with no vulnerability details, and we will follow up.

### What to include

A good report helps us reproduce and fix the issue quickly. Where possible:

- A clear description of the vulnerability and its impact. The affected component (ex. OIDC token endpoint, CAS validation, session handling, MFA, federation callback, the reverse-proxy `verify` endpoint, the admin API).
- Step-by-step reproduction instructions, including any configuration, request payloads, or preconditions.
- A proof of concept if you have one.
- The commit hash or version you tested against.
- Any suggested remediation, if you have thoughts.

## What to expect

This is an open-source project maintained on a best-effort basis. We don't promise a fixed response-time, but we will:

- Acknowledge your report as soon as we reasonably can.
- Keep you updated on our assessment and progress.
- Let you know if we need more information.
- Credit you in the published advisory once a fix is released, unless you prefer to remain anonymous.

We ask that you give us a reasonable opportunity to address the issue before any public disclosure, and that we coordinate on timing together.

## Supported versions

This project has not yet cut tagged releases. It is **pre-release**, and security fixes land on the `main` branch. If you run this server, track
`main` for security updates.

Once versioned releases exist, this section will list which versions receive security fixes. Until then, "supported" means the current `main`.

## Scope

We are most interested in vulnerabilities that undermine the security guarantees an identity server is supposed to provide, including but not limited to:

- **Authentication bypass**: logging in as another user, or without valid credentials.
- **Token forgery or leakage**: minting, tampering with, or extracting access tokens, refresh tokens, ID tokens, CAS tickets, or session cookies; signature-verification flaws; algorithm-confusion attacks.
- **Authorization / privilege escalation**: gaining admin rights, or acting on another user's behalf; flaws in the admin API's access control.
- **MFA bypass**: completing authentication without satisfying an enrolled second factor, or defeating the force-MFA policy.
- **Federation trust-boundary flaws**: issues in how upstream identities (Google, GitHub, generic OIDC) are verified and mapped to local accounts, account-linking or takeover via federation.
- **Protocol-level flaws**: in the OIDC / OAuth 2 or CAS implementations (ex. PKCE downgrade, redirect-URI validation bypass, nonce/state handling, authorization-code replay).
- **Injection**: SQL injection, or injection through any user-controlled field that reaches a sensitive sink.
- **Session-management flaws**: fixation, improper invalidation, or cross-session leakage.
- **CSRF**: on state-changing endpoints, or weaknesses in the double-submit token mechanism.

### Generally out of scope

These are usually not treated as vulnerabilities on their own. Report them if you can show concrete security impact, but expect them to be lower priority:

- Findings that require a misconfigured deployment contrary to the documented guidance (for example, running without TLS in production, or exposing the admin API to the public internet by choice).
- Missing security headers or cookie flags on a local/dev (`http://localhost`) deployment, where they are intentionally relaxed.
- Self-XSS that requires the victim to paste attacker-supplied content into their own browser console.
- Rate-limiting or brute-force concerns without a demonstrated bypass of the existing protections.
- Output of automated scanners without a demonstrated, exploitable impact.
- Denial of service through sheer volume of traffic (as opposed to an algorithmic-complexity or amplification flaw that a single request can trigger).
- Vulnerabilities in dependencies that are already public and tracked upstream, though a report explaining how this project is specifically exposed is welcome.

## Safe harbor

We consider security research and vulnerability disclosure conducted in good faith under this policy to be authorized. We will not pursue or support legal action against researchers who:

- Make a good-faith effort to follow this policy.
- Only interact with systems and accounts they own or have explicit permission to test (please test against your **own** deployment, never against someone else's live instance).
- Avoid privacy violations, data destruction, and service degradation.
- Give us a reasonable chance to remediate before disclosing publicly.

If in doubt about whether your testing is acceptable, ask first through the private reporting channel above.

## A note on testing

Because this is software you self-host, the right way to test is to run your **own** instance and probe that. Do not test against deployments you do not control
That is both out of scope for safe harbor and potentially illegal.
