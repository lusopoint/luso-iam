.PHONY: help build run dev-server test test-unit test-cover lint tidy \
        compose-up compose-down compose-logs compose-clear \
        migrate-up migrate-down migrate-new \
        web-install web-build web-dev web-clean \
        keygen seed-client grant-admin seed-user \
        docker-build docker-run docker-push

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
test: ## run all unit tests (race detector, fresh cache)
	go test ./... -race -count=1

test-unit: ## run fast unit tests only (skip the future testcontainers-based suites)
	go test ./internal/crypto/... ./internal/auth/mfa/... ./internal/api/mfa/... ./internal/config/... ./internal/api/cas/... ./pkg/... ./internal/oidc/... -race -count=1

test-cover: ## run unit test only with -cover
	go test -cover ./internal/crypto/... ./internal/auth/mfa/... ./internal/api/cas/... ./pkg/...

tidy: ## tidy go.mod and verify
	go mod tidy
	go mod verify

compose-up: ## local infra (Postgres)
	docker compose -f deployments/docker-compose.dev.yml up -d

compose-down: ## down the services (without cleaning the volumes)
	docker compose -f deployments/docker-compose.dev.yml down

compose-clear: ## down and fully clean the volumes
	docker compose -f deployments/docker-compose.dev.yml down --remove-orphans --volumes

compose-logs: ## display logs (only postgres)
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

# Web (react front end)
# `make build` depends on web-build so a single command produces a binary
# with the compiled SPA embedded. Web-build short-circuits via the
# node_modules timestamp marker so iterative server builds aren't slow

web-install: ## Install web dependencies (npm handles its own caching)
	cd $(WEB_DIR) && npm install --no-audit --no-fund

web-build: web-install ## Build the React admin SPA into web/dist
	cd $(WEB_DIR) && npm run build

web-dev: web-install ## Start the Vite dev server (with API proxy to :8080)
	cd $(WEB_DIR) && npm run dev

web-clean: ## Remove web/dist (resets to stub on next web-build)
	rm -rf $(WEB_DIR)/dist/assets
	git checkout $(WEB_DIR)/dist/index.html 2>/dev/null || true

# key management

keygen: ## Generate an RSA-2048 signing key at ./signing.pem (dev use)
	openssl genrsa -out signing.pem 2048
	@echo "Set SIGNING_KEY_PATH=$$PWD/signing.pem in your .env"

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

# Docker
# Build a production-ready container image
DOCKER_FILE ?= deployments/Dockerfile
IMAGE_TAG   ?= iam-server:$(VERSION)

docker-build: ## Build the production container image
	docker build \
	  -f $(DOCKER_FILE) \
	  --build-arg VERSION=$(VERSION) \
	  -t $(IMAGE_TAG) \
	  .

docker-run: ## Boot the production compose stack (postgres + iam + caddy)
	cd deployments && docker compose up --detach --build

docker-push: ## Push the image (requires IMAGE_TAG to point at a registry)
	docker push $(IMAGE_TAG)

