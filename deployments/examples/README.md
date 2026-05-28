# Forward-auth deployment examples

This directory holds runnable Compose stacks demonstrating the IAM
server's reverse-proxy companion (the `/proxy/verify` endpoint) with
two common reverse proxies. Each is self-contained — start it with
`docker compose up` from inside the relevant subdirectory.

| Directory              | What it shows                                                    |
| ---------------------- | ---------------------------------------------------------------- |
| `caddy-forwardauth/`   | IAM behind Caddy, protecting a downstream app via `forward_auth` |
| `traefik-forwardauth/` | Same scenario, but with Traefik's `ForwardAuth` middleware       |

For a non-example deployment (no demo-app, no forward-auth — just IAM
behind Caddy), see the top-level `deployments/docker-compose.yml`.

## Caddy vs Traefik — which to pick?

| Question                                                               | Caddy                 | Traefik            |
| ---------------------------------------------------------------------- | --------------------- | ------------------ |
| Working on a single VM with files-on-disk config?                      | ✓ — short Caddyfile   | overkill           |
| Already running Kubernetes / Swarm with label-based service discovery? | possible but awkward  | ✓ — built for this |
| Need automatic TLS with zero ceremony?                                 | ✓ default behaviour   | ✓ via ACME         |
| Want a metrics dashboard out of the box?                               | metrics endpoint only | ✓ web dashboard    |

The IAM server doesn't care which one you use — the `/proxy/verify`
endpoint speaks the standard forward-auth contract. Both examples are
maintained; pick whichever fits the rest of your infrastructure.

## Required IAM env vars for forward-auth

Both examples set these on the `iam` service; they're not specific to
either proxy:

```bash
SESSION_COOKIE_DOMAIN=.example.com           # parent domain shared by all protected apps
PROXY_ALLOWED_CALLBACK_ORIGINS=https://app.example.com,https://wiki.example.com
```

`BASE_URL=https://...` should also be set to the public auth URL —
the `https` scheme is what turns on the Secure flag on cookies, and
the host portion is the WebAuthn RPID. Both are derived automatically
from `BASE_URL`, so there's no separate env var to manage.

Why the two above matter:

- **`SESSION_COOKIE_DOMAIN`** — without this, the session cookie is
  scoped to `auth.example.com` only. Caddy/Traefik forwards the user's
  cookies on the verify sub-request, but if the user's browser doesn't
  have an IAM session cookie for `app.example.com`, the proxy gets
  nothing to forward. Setting the cookie's `Domain` attribute to the
  parent makes it readable across subdomains.

- **`PROXY_ALLOWED_CALLBACK_ORIGINS`** — `/proxy/verify` only adds a
  `Location` header to its 401 responses when the requested origin
  (reconstructed from `X-Forwarded-*`) is in this list. Without it,
  the browser sees a bare 401 instead of being redirected to login.
  The allowlist is an open-redirect defence — without it, anyone able
  to send forged `X-Forwarded-Host` could turn the IAM server into an
  open redirect.
