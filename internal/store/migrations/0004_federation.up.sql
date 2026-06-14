-- links IAM users to provider identities (Google, GitHub, etc.)
-- 1 row per (provider, sub) pair: a user can have multiple upstream identities
-- but each provider account maps to exactly one IAM user
CREATE TABLE user_identities (
    id           uuid        PRIMARY KEY DEFAULT uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- provider slug: "google", "github", "microsoft", "gitlab", "apple",
    -- or a custom slug for generic OIDC/OAuth2 providers
    provider     text        NOT NULL,
    -- the providers stable user identifier (OIDC sub claim, GitHub user id,
    -- we never use the email because it can change
    sub          text        NOT NULL,
    -- cached from the last login, shown in admin UI and used for account linking prompts
    email        citext      NULL,
    display_name text        NULL,
    picture_url  text        NULL,

    -- full claims/user object from the last token exchange, stored for
    -- audit and for future attribute release without re fetching
    raw_claims   jsonb       NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_identities_provider_sub_uq UNIQUE (provider, sub)
);

CREATE INDEX user_identities_user_id_idx ON user_identities (user_id);
CREATE TRIGGER user_identities_touch_updated_at
    BEFORE UPDATE ON user_identities
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

