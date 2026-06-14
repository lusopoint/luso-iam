-- the client_id is the primary key short random or readable
CREATE TABLE oidc_clients (
    id                  text        PRIMARY KEY,
    secret_hash         text        NULL,
    name                text        NOT NULL,
    -- exact redirect_uris, wildcards are NOT allowed per spec
    redirect_uris       text[]      NOT NULL,
    allowed_scopes      text[]      NOT NULL DEFAULT '{openid,profile,email}',
    -- supported grant types for this client
    allowed_grant_types text[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    is_public           boolean     NOT NULL DEFAULT false,
    require_pkce        boolean     NOT NULL DEFAULT true,
    require_consent     boolean     NOT NULL DEFAULT false,
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

-- oidc_auth_codes, short lived (~10 min) authorization codes
-- single use, consumed atomically by the token endpoint
CREATE TABLE oidc_auth_codes (
    id              text        PRIMARY KEY,
    client_id       text        NOT NULL REFERENCES oidc_clients(id),
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      uuid        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    redirect_uri    text        NOT NULL,
    scopes          text[]      NOT NULL,
    nonce           text        NULL,
    pkce_challenge  text        NULL,
    -- authentication context at time of issuance
    acr             text        NOT NULL DEFAULT '0',
    amr             text[]      NOT NULL DEFAULT '{pwd}',
    auth_time       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_auth_codes_expires_idx ON oidc_auth_codes (expires_at) WHERE consumed_at IS NULL;

-- opaque bearer tokens introspect / userInfo do a direct db lookup by token id
CREATE TABLE oidc_access_tokens (
    id          text        PRIMARY KEY,
    client_id   text        NOT NULL REFERENCES oidc_clients(id),
    user_id     uuid        NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id  uuid        NULL REFERENCES sessions(id) ON DELETE SET NULL,
    scopes      text[]      NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_access_tokens_expires_idx ON oidc_access_tokens (expires_at) WHERE revoked_at IS NULL;

-- long lived tokens redeemed for new access tokens
-- refresh token rotation, each use consumes the token and issues a new one
CREATE TABLE oidc_refresh_tokens (
    id              text        PRIMARY KEY,
    client_id       text        NOT NULL REFERENCES oidc_clients(id),
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      uuid        NULL REFERENCES sessions(id) ON DELETE SET NULL,
    scopes          text[]      NOT NULL,
    previous_id     text        NULL,
    expires_at      timestamptz NOT NULL,
    rotated_at      timestamptz NULL,
    revoked_at      timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oidc_refresh_tokens_expires_idx
    ON oidc_refresh_tokens (expires_at)
    WHERE revoked_at IS NULL AND rotated_at IS NULL;
