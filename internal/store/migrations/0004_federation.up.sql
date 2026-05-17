-- 0004_federation.up.sql
-- Links canonical IAM users to upstream provider identities (Google,
-- GitHub, etc.). One row per (provider, sub) pair — a user can have
-- multiple upstream identities but each provider account maps to exactly
-- one IAM user.

BEGIN;

CREATE TABLE user_identities (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Provider slug: "google", "github", "microsoft", "gitlab", "apple",
    -- or a custom slug for generic OIDC/OAuth2 providers.
    provider     text        NOT NULL,

    -- The provider's stable user identifier (OIDC sub claim, GitHub user id,
    -- etc.). Stable: we never use the email because those can change.
    sub          text        NOT NULL,

    -- Cached from the last login — shown in admin UI and used for
    -- account-linking prompts. Not authoritative; do not use for authz.
    email        citext      NULL,
    display_name text        NULL,
    picture_url  text        NULL,

    -- Full claims/user object from the last token exchange, stored for
    -- audit and for future attribute release without re-fetching.
    raw_claims   jsonb       NOT NULL DEFAULT '{}',

    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    -- Each provider account links to exactly one IAM user.
    CONSTRAINT user_identities_provider_sub_uq UNIQUE (provider, sub)
);

-- Efficient lookup of all identities for a user (e.g. profile page,
-- account unlinking).
CREATE INDEX user_identities_user_id_idx
    ON user_identities (user_id);

CREATE TRIGGER user_identities_touch_updated_at
    BEFORE UPDATE ON user_identities
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

COMMIT;
