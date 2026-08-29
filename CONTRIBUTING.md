# Contributing

Thanks for considering a contribution to IAM Server. This is a self-hosted identity server, correctness and security bugs here have outsized impact, so the bar for changes touching auth, tokens, sessions, or crypto is higher than a typical web app.

## Before you start

- For anything beyond a small fix (a new feature, a protocol change, a new dependency), open an issue first to align on approach before writing code.

- Found a security vulnerability? Do **not** open a public issue or PR, see more [SECURITY.md](SECURITY.md) for private disclosure.

## Local setup

See the [Quick start](README.md#quick-start) section in the README:

```bash
make compose-dev-up
make keygen
# create a .env (see README), then:
make migrate-up
make seed-user email=you@example.com password=devpass123 admin=1
make dev-server   # Terminal A: backend on :8080
make web-dev      # Terminal B: web UI with hot reload on :5173
```

## Before opening a pull request

```bash
make lint   # gofmt + go vet + Biome
make test   # go test -race ./...
```

Both must pass! CI runs the same checks (`.github/workflows/`) plus a build of the Go binary and the SPA.
So a green `make lint && make test` locally is a strong signal your PR will pass CI too.

## Conventions

- **Branches:** prefix with `feat-`, `fix-`, `chore-`, `docs-`, `test-`.

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/)(`feat(mfa): add WebAuthn enrollment`).

- **PRs:** need passing CI, two approval, and no lint warnings.

## Dependencies

The `go.mod` runtime `require` section is kept deliberately short, you can see `SYSTEM.md`("Dependency philosophy").
If your PR adds a new runtime dependency, justify it in the commit message against that system(protocol/spec implementation with real attack surface vs. glue code that stdlib already covers). Dev-time-only tools (code generators, migration tooling) are held to a lower bar.

## Code style

- Go: standard `gofmt`; no linter config beyond `go vet` today.

- Web: TypeScript strict mode, Biome for lint + format(`make web-lint` / `make web-format`).

- Sentinel errors per package (`var ErrNotFound = errors.New(...)`), wrapped with context (`fmt.Errorf("getUser: %w", err)`). HTTP handlers translate domain errors to RFC 7807 Problem JSON, you can see any handler in `internal/api/*` for the pattern.

## Tests

- Unit tests live alongside the code (`foo_test.go`).
- Changes to `internal/oidc`, `internal/auth/*`, or `internal/crypto`(anything on the authentication or token path) should come with tests covering the new behavior, not just the happy path, these are the packages where a silent regression has the highest impact.

## Docs

If your change affects configuration, an environment variable, or a documented flow, update the in-app docs page content(`internal/api/docs/`) and `deployments/.env.example` alongside the code, not as an afterthought!
