-- one row per user storing the argon2id-encoded password hash
CREATE TABLE user_credentials (
    user_id              uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash        text        NOT NULL,
    password_changed_at  timestamptz NOT NULL DEFAULT now(),
    must_change          boolean     NOT NULL DEFAULT false,
    failed_attempts      integer     NOT NULL DEFAULT 0,
    locked_until         timestamptz NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER user_credentials_touch_updated_at
    BEFORE UPDATE ON user_credentials
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- browser sessions to the IAM portal
-- the session id is stored in a signed cookie, this row holds the actual state
-- doubles as the CAS ticket granting ticket, example when a CAS service
-- ticket is minted it is bound to a session_id
CREATE TABLE sessions (
    id            uuid        PRIMARY KEY DEFAULT uuid(),
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    ip_address    inet        NULL,
    user_agent    text        NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz NULL
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at) WHERE revoked_at IS NULL;

