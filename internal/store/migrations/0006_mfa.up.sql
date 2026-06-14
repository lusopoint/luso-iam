-- enrolled second factors, One row per registered method per user
-- the method column drives which payload columns are read:
--
-- method='totp'     -> secret  (base32 shared secret)
-- method='webauthn' -> credential (JSON-encoded webauthn.Credential),
--                      counter (sign-count for clone detection)
--
-- a method is only usable after confirmed_at is set, for TOTP this happens
-- on first successful verification, for WebAuthn on successful registration
CREATE TABLE user_mfa_methods (
    id            uuid        PRIMARY KEY DEFAULT uuid(),
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method        text        NOT NULL
                  CHECK (method IN ('totp', 'webauthn')),
    name          text        NULL,
    secret        text        NULL,
    credential    jsonb       NULL,
    counter       bigint      NOT NULL DEFAULT 0,

    confirmed_at  timestamptz NULL,
    last_used_at  timestamptz NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_mfa_methods_user_idx ON user_mfa_methods (user_id) WHERE confirmed_at IS NOT NULL;

CREATE INDEX user_mfa_methods_user_method_idx
    ON user_mfa_methods (user_id, method)
    WHERE confirmed_at IS NOT NULL;

CREATE TRIGGER user_mfa_methods_touch_updated_at
    BEFORE UPDATE ON user_mfa_methods
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- single use recovery codes, each row stores the argon2id hash of one code
-- A user's full set is replaced atomically when they regenerate
CREATE TABLE user_backup_codes (
    id          uuid        PRIMARY KEY DEFAULT uuid(),
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   text        NOT NULL,
    used_at     timestamptz NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_backup_codes_active_idx
    ON user_backup_codes (user_id)
    WHERE used_at IS NULL;

-- carry the authentication context so OIDC id_tokens can emit
-- the correct acr / amr claims downstream
--   acr='0' = no MFA (password / federation only)
--   acr='1' = MFA succeeded
--   amr     = list of authentication methods used during this session
--             ['pwd'], ['pwd','otp'], ['fed','google'], ['hwk']
ALTER TABLE sessions
    ADD COLUMN acr text   NOT NULL DEFAULT '0',
    ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
