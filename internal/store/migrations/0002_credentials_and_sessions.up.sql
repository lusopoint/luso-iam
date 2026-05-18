-- 0002_credentials_and_sessions.up.sql
-- Password credentials and browser sessions.

BEGIN;

-- user_credentials: one row per user storing the argon2id-encoded
-- password hash. Future credential types (passkeys etc.) live in their
-- own tables (e.g. user_mfa_methods).
CREATE TABLE user_credentials (
    user_id              uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- Full PHC-format argon2id string, e.g. $argon2id$v=19$m=65536,t=3,p=4$...$...
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

-- sessions: browser sessions to the IAM portal. The session id is stored
-- in a signed cookie; this row holds the actual state. The session
-- doubles as the CAS Ticket-Granting Ticket — i.e. when a CAS service
-- ticket is minted it is bound to a session_id.
CREATE TABLE sessions (
    id            uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Absolute expiry; the session dies at this point regardless of activity.
    expires_at    timestamptz NOT NULL,
    -- Sliding-expiry anchor; updated on every authenticated request.
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    ip_address    inet        NULL,
    user_agent    text        NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz NULL
);

CREATE INDEX sessions_user_id_idx
    ON sessions (user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_expires_at_idx
    ON sessions (expires_at)
    WHERE revoked_at IS NULL;

COMMIT;
