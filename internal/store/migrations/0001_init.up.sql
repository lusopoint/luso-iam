-- pgcrypto is needed for gen_random_bytes (used by our UUIDv7 helper)
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- citext gives us case insensitive email comparisons without lower() everywhere
CREATE EXTENSION IF NOT EXISTS citext;

-- in the leading 48 bits, then version + variant bits, then 74 random bits
-- time sortable, index friendly, no client coordination needed
CREATE OR REPLACE FUNCTION uuid() RETURNS uuid AS $$
DECLARE
    unix_ts_ms bytea;
    uuid_bytes bytea;
BEGIN
    unix_ts_ms := substring(
        int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint)
        FROM 3
    );
    uuid_bytes := unix_ts_ms || gen_random_bytes(10);
    uuid_bytes := set_byte( uuid_bytes, 6, (112 | (get_byte(uuid_bytes, 6) & 15)));
    uuid_bytes := set_byte( uuid_bytes, 8, (128 | (get_byte(uuid_bytes, 8) & 63)));

    RETURN encode(uuid_bytes, 'hex')::uuid;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- touch_updated_at(), trigger function to bump updated_at on UPDATE
-- attached to each table that has updated_at
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- user record
-- credentials, MFA, sessions, etc
-- live in separate tables added later
CREATE TABLE users (
    id              uuid        PRIMARY KEY DEFAULT uuid(),
    email           citext      NULL,
    username        text        NULL,
    display_name    text        NULL,
    status          text        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'locked', 'disabled')),
    email_verified_at timestamptz NULL,
    last_login_at   timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz NULL
);

CREATE UNIQUE INDEX users_email_active_uq
    ON users (email)
    WHERE deleted_at IS NULL AND email IS NOT NULL;

CREATE UNIQUE INDEX users_username_active_uq
    ON users (username)
    WHERE deleted_at IS NULL AND username IS NOT NULL;

CREATE INDEX users_created_at_idx ON users (created_at);

CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

