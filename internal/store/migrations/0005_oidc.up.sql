-- 0005_oidc.up.sql
-- OIDC / OAuth 2.0 client registry and ephemeral token tables.

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────
-- oidc_clients: registered OAuth 2.0 / OIDC client applications.
-- The client_id is the primary key — short random or human-readable.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE oidc_clients (
    id                  text        PRIMARY KEY,
    -- argon2id hash of the client_secret. NULL for public clients.
    secret_hash         text        NULL,
    name                text        NOT NULL,
    -- Exact redirect_uris — wildcards are NOT allowed per spec.
    redirect_uris       text[]      NOT NULL,
    allowed_scopes      text[]      NOT NULL DEFAULT '{openid,profile,email}',
    -- Supported grant types for this client.
    allowed_grant_types text[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    is_public           boolean     NOT NULL DEFAULT false,
    -- If true, client MUST supply code_challenge (PKCE). Public clients
    -- always require PKCE regardless of this flag.
    require_pkce        boolean     NOT NULL DEFAULT true,
    -- If false, skip the consent screen (typical for first-party clients).
    require_consent     boolean     NOT NULL DEFAULT false,
    -- Token lifetimes; overrides server defaults per client.
    access_token_ttl    interval    NOT NULL DEFAULT '1 hour',
    refresh_token_ttl   interval    NOT NULL DEFAULT '30 days',
    id_token_ttl        interval    NOT NULL DEFAULT '1 hour',
    enabled             boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz NULL
);

CREATE TRIGGER oidc_clients_touch_updated_at
    BEFORE UPDATE ON oidc_clients
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ─────────────────────────────────────────────────────────────────────────
-- oidc_auth_codes: short-lived (≤10 min) authorization codes.
-- Single-use: consumed atomically by the token endpoint.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE oidc_auth_codes (
    id              text        PRIMARY KEY,  -- "code_<32 hex>"
    client_id       text        NOT NULL REFERENCES oidc_clients(id),
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      uuid        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri    text        NOT NULL,
    scopes          text[]      NOT NULL,
    nonce           text        NULL,
    -- S256 code_challenge stored at issue time; verifier checked at exchange.
    pkce_challenge  text        NULL,
    -- Authentication context at time of issuance.
    acr             text        NOT NULL DEFAULT '0',
    amr             text[]      NOT NULL DEFAULT '{pwd}',
    auth_time       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_auth_codes_expires_idx
    ON oidc_auth_codes (expires_at)
    WHERE consumed_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- oidc_access_tokens: opaque bearer tokens.
-- Introspect / UserInfo do a direct DB lookup by token id.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE oidc_access_tokens (
    id          text        PRIMARY KEY,  -- "at_<32 hex>"
    client_id   text        NOT NULL REFERENCES oidc_clients(id),
    -- NULL for client_credentials grant (no user).
    user_id     uuid        NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id  uuid        NULL REFERENCES sessions(id) ON DELETE SET NULL,
    scopes      text[]      NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_access_tokens_expires_idx
    ON oidc_access_tokens (expires_at)
    WHERE revoked_at IS NULL;

-- ─────────────────────────────────────────────────────────────────────────
-- oidc_refresh_tokens: long-lived tokens redeemed for new access tokens.
-- Refresh token rotation: each use consumes the token and issues a new one.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE oidc_refresh_tokens (
    id              text        PRIMARY KEY,  -- "rt_<32 hex>"
    client_id       text        NOT NULL REFERENCES oidc_clients(id),
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      uuid        NULL REFERENCES sessions(id) ON DELETE SET NULL,
    scopes          text[]      NOT NULL,
    -- The previous token id in the rotation chain. Detecting reuse of a
    -- rotated token means the chain has been compromised; revoke the family.
    previous_id     text        NULL,
    expires_at      timestamptz NOT NULL,
    rotated_at      timestamptz NULL,  -- set when consumed and rotated
    revoked_at      timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_refresh_tokens_expires_idx
    ON oidc_refresh_tokens (expires_at)
    WHERE revoked_at IS NULL AND rotated_at IS NULL;

COMMIT;
