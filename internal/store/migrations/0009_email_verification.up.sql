-- Email verification tokens.
--
-- Issued at signup (and potentially at email-change time, later). The
-- token is a high-entropy random string sent to the user's email; the
-- DB stores only the sha256 hash so a DB leak doesn't hand the
-- attacker live verification tokens.
--
-- Same shape as 0008's password_reset_tokens, deliberately: the two
-- flows are conceptually parallel and reusing the schema makes the
-- service code easier to compare and reason about. Kept as a separate
-- table because:
--   1. TTLs differ (verification ~ 24h, reset ~ 30min)
--   2. Lifecycle differs (verification is one-shot at account birth,
--      reset can recur)
--   3. Mixing them would force every query to filter on a "kind"
--      column, adding latency to a hot path
--
-- Tokens are single-use: used_at is set when consumed, and subsequent
-- attempts with the same token fail.
CREATE TABLE email_verification_tokens (
    -- token_hash is sha256(token_bytes) hex-encoded. PRIMARY KEY so a
    -- lookup is O(1); also gives us a uniqueness constraint for free.
    token_hash  TEXT        PRIMARY KEY,

    user_id     UUID        NOT NULL
                            REFERENCES users(id) ON DELETE CASCADE,

    -- email captures the address being verified. We snapshot it at
    -- issue time so that a later email-change-then-verify race can't
    -- accidentally verify the wrong address.
    email       TEXT        NOT NULL,

    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- request_ip + user_agent capture the originating client. Useful
    -- for the audit log and abuse investigation.
    request_ip  TEXT,
    user_agent  TEXT
);

-- Index by user so we can quickly invalidate all outstanding tokens
-- (e.g., on email change or account compromise).
CREATE INDEX email_verification_tokens_user_id_idx
    ON email_verification_tokens(user_id);

-- Index by expiry for periodic cleanup of stale rows. Not used at
-- request time, only by a future janitor.
CREATE INDEX email_verification_tokens_expires_at_idx
    ON email_verification_tokens(expires_at);

