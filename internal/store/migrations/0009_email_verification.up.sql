CREATE TABLE email_verification_tokens (
    token_hash  TEXT        PRIMARY KEY,
    user_id     UUID        NOT NULL
                            REFERENCES users(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- request_ip + user_agent capture the originating client, useful
    -- for the audit log and abuse investigation
    request_ip  TEXT,
    user_agent  TEXT
);

CREATE INDEX email_verification_tokens_user_id_idx ON email_verification_tokens(user_id);
CREATE INDEX email_verification_tokens_expires_at_idx ON email_verification_tokens(expires_at);

