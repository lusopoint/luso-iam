.PHONY: help build run dev-server smoke-test test test-cover lint tidy \
        compose-dev-up compose-dev-down compose-dev-logs compose-dev-clear \
        migrate-up migrate-down migrate-new migrate-container \
        web-install web-ci-install web-build web-dev web-clean web-lint web-format sync-tokens \
        keygen rotate-key seed-client grant-admin seed-user \
        prod-build prod-run prod-push vuln vuln-web

# TODO: should we just trust the one on the .env?
DATABASE_URL ?= postgres://iam:iam@localhost:5432/iam?sslmode=disable
MIGRATIONS_DIR := internal/store/migrations
WEB_DIR := web

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

help:
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ \
		{ printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# build & run
build: web-build ## compile the server binary (with embedded SPA) into ./bin/iam-server
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/iam-server ./cmd/server

run: build ## build (web + server) and run
	./bin/iam-server

# only for development
dev-server: ## run the server directly with `go run` (uses stub SPA unless web-build was run)
	go run ./cmd/server

# testing
test: ## run all unit tests
	go test ./... -race -count=1

test-cover: ## run test only with -cover
	go test -cover ./...

lint: web-lint ## gofmt + go vet (Go) and Biome (web) - mirrors CI's format checks
	@unformatted="$$(gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...

smoke-test: ## black-box test against the running application (BASE_URL=http://localhost:8080)
	@BASE_URL="$${BASE_URL:-http://localhost:8080}" ./scripts/smoke-test.sh

tidy: ## tidy go.mod and verify
	go mod tidy
	go mod verify

compose-dev-up: ## locally, just builds postgres
	docker compose -f deployments/docker-compose.dev.yml up -d

compose-dev-down: ## down the services (without cleaning the volumes)
	docker compose -f deployments/docker-compose.dev.yml down

compose-dev-clear: ## down and fully clean the volumes
	docker compose -f deployments/docker-compose.dev.yml down --remove-orphans --volumes

compose-dev-logs: ## display postgres logs
	docker compose -f deployments/docker-compose.dev.yml logs -f postgres

# migrations
# automatic if AUTO_MIGRATE=true

migrate-up: ## apply all pending migrations
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down: ## roll back the most recent migration
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-new: ## create a new migration pair: - make migrate-new name=add_foo
	@[ -n "$(name)" ] || (echo "usage: make migrate-new name=add_foo" && exit 1)
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $(name)

migrate-container: ## apply pending migrations via the same /migrate binary shipped in the container image (cmd/migrate) - the AUTO_MIGRATE=false deploy step, no external `migrate` CLI needed
	@DATABASE_URL="$(DATABASE_URL)" go run ./cmd/migrate

# Web react front end
# `make build` depends on web-build so a single command produces a binary
# with the compiled SPA embedded

web-install: ## Install react dependencies (npm handles its own caching)
	cd $(WEB_DIR) && npm install --no-audit --no-fund

# npm ci, not install: matches CI's own install step exactly, so a
# package-lock.json that's out of sync with package.json fails loudly here
# too, instead of `npm install` silently rewriting it into whatever shape
# the local npm happens to produce. (This is how a lockfile that passed
# local `make lint` still failed CI's `npm ci` — a Tailwind v4 optional
# dependency that different npm patch versions resolve differently.)
web-ci-install: ## Install react dependencies exactly as CI does (npm ci)
	cd $(WEB_DIR) && npm ci --no-audit --no-fund

web-build: web-install sync-tokens ## Build the React admin SPA into web/dist
	cd $(WEB_DIR) && npm run build

# The server-rendered pages (CAS login, MFA, consent, signup, password reset)
# are plain HTML + CSS with no build step, but they use the same design tokens
# as the admin SPA. Rather than maintain a second copy of the palette (which is
# what the fourteen old <style> blocks did, and they had already drifted), we
# copy LusoUI's palette.css straight into the embedded static dir.
#
# palette.css is deliberately framework-free: no @theme, no @apply, just custom
# properties, precisely so a Go template can consume it as-is.
sync-tokens: web-install ## Copy LusoUI design tokens into the Go-embedded static assets
	@printf '/* GENERATED FILE, DO NOT EDIT!\n * Run `make sync-tokens`. Source: @lusopoint/luso-ui/src/styles/palette.css\n * Edit the tokens there; they are shared with the admin SPA.\n *\n * The @font-face import is stripped on purpose: the auth pages make ZERO\n * external requests (the SSO icons are inlined SVG for the same reason), so\n * they never tell Google that a given user is sitting on a login page. It is\n * also blocked by our CSP (style-src self). The pages fall back to system-ui.\n */\n\n' \
		> internal/api/web/static/tokens.css
	@grep -v "fonts.googleapis.com" \
		$(WEB_DIR)/node_modules/@lusopoint/luso-ui/src/styles/palette.css \
		>> internal/api/web/static/tokens.css
	@echo "  synced design tokens -> internal/api/web/static/tokens.css"

web-dev: web-install ## Start the Vite dev server (with API proxy to :8080)
	cd $(WEB_DIR) && npm run dev

web-lint: web-ci-install ## Lint + format-check the SPA with Biome (no writes) - mirrors CI's install step too
	cd $(WEB_DIR) && npm run check

web-format: web-install ## Auto-fix Biome lint + formatting in the SPA
	cd $(WEB_DIR) && npm run check:write

web-clean: ## Remove web/dist (resets to stub on next web-build)
	rm -rf $(WEB_DIR)/dist/assets
	git checkout $(WEB_DIR)/dist/index.html 2>/dev/null || true

# key management

keygen: ## Generate an RSA-2048 signing key at ./signing.pem (dev use)
	openssl genrsa -out signing.pem 2048
	@echo "Set SIGNING_KEY_PATH=$$PWD/signing.pem in your .env"

rotate-key: ## generate a new signing key in a keys directory (rotate=path; ex. make rotate-key dir=/etc/iam/keys)
	@[ -n "$(dir)" ] || (echo "usage: make rotate-key dir=/path/to/keys" && exit 1)
	go run ./cmd/rotate-key -dir "$(dir)"

# Seed helpers (dev only) it will help with the creation on admin users and other usefull commands

seed-client: ## register a test OIDC client (requires DATABASE_URL)
	@echo "Seeding test OIDC client..."
	psql "$(DATABASE_URL)" -c \
	  "INSERT INTO oidc_clients (id, name, redirect_uris, is_public, require_pkce, require_consent) \
	   VALUES ('test-client', 'Test SPA', '{http://localhost:3000/callback}', true, true, false) \
	   ON CONFLICT (id) DO NOTHING;"
	@echo "client_id: test-client (public, PKCE required)"

grant-admin: ## promote a user to admin: make grant-admin email=l@mail.com
	@[ -n "$(email)" ] || (echo "usage: make grant-admin email=user@example.com" && exit 1)
	@psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -c \
	  "UPDATE users SET is_admin = true WHERE email = '$(email)' RETURNING id, email, is_admin;"
	@echo "Promotion complete. The user can now sign in at /cas/login and access /admin."

seed-user: ## create a user: make seed-user email=l@main.com password=password123 [admin=1] [name="lee"]
	@[ -n "$(email)" ]    || (echo "usage: make seed-user email=... password=... [admin=1] [name=...]" && exit 1)
	@[ -n "$(password)" ] || (echo "password is required" && exit 1)
	@DATABASE_URL="$(DATABASE_URL)" go run ./cmd/seed-user \
	  -email "$(email)" \
	  -password "$(password)" \
	  $(if $(name),-name "$(name)") \
	  $(if $(admin),-admin)

# Build a production-ready container image
DOCKER_FILE ?= deployments/Dockerfile
IMAGE_TAG   ?= iam-server:$(VERSION)

prod-build: ## Build the production container image
	docker build \
	  -f $(DOCKER_FILE) \
	  --build-arg VERSION=$(VERSION) \
	  -t $(IMAGE_TAG) \
	  .

prod-run: ## Boot the production compose stack (postgres + iam)
	cd deployments && docker compose up --detach --build

prod-push: ## Push the image (requires IMAGE_TAG to point at a registry)
	docker push $(IMAGE_TAG)

vuln: ## scan Go dependencies for known vulnerabilities (govulncheck)
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

vuln-web: ## scan the SPA's production dependencies (npm audit, high+)
	@cd web && npm audit --omit=dev --audit-level=high
