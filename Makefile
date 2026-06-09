.PHONY: help build run dev-server smoke-test test test-cover tidy \
        compose-dev-up compose-dev-down compose-dev-logs compose-dev-clear \
        migrate-up migrate-down migrate-new \
        web-install web-build web-dev web-clean \
        keygen rotate-key seed-client grant-admin seed-user \
        prod-build prod-run prod-push

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

# Web react front end
# `make build` depends on web-build so a single command produces a binary
# with the compiled SPA embedded

web-install: ## Install react dependencies (npm handles its own caching)
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

prod-run: ## Boot the production compose stack (postgres + iam + caddy)
	cd deployments && docker compose up --detach --build

prod-push: ## Push the image (requires IMAGE_TAG to point at a registry)
	docker push $(IMAGE_TAG)

