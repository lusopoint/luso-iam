CREATE TABLE password_reset_tokens (
    -- token_hash is sha256(token_bytes)
    token_hash  TEXT        PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- expires_at is enforced server-side; an expired token also fails even
    expires_at  TIMESTAMPTZ NOT NULL,
    -- tokens are single use: used_at is set when consumed
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- request_ip + user_agent capture the originating client
    -- Useful for the audit log and for showing the user "this reset was
    -- requested from <IP>" if we add that to the email later
    request_ip  TEXT,
    user_agent  TEXT
);

CREATE INDEX password_reset_tokens_user_id_idx
    ON password_reset_tokens(user_id);

CREATE INDEX password_reset_tokens_expires_at_idx
    ON password_reset_tokens(expires_at);

