-- 0001_init.up.sql
-- Foundation: extensions, conventions helpers, and the canonical users table.

BEGIN;

-- pgcrypto is needed for gen_random_bytes (used by our UUIDv7 helper).
-- gen_random_uuid (v4) ships in core since Postgres 13 but we want v7 for
-- time-sortability per guidelines section 5.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- citext gives us case-insensitive email comparisons without lower()
-- everywhere. Ships in standard contrib on every major Postgres distro
-- and managed service (RDS, Cloud SQL, Azure, Supabase, Neon, …).
CREATE EXTENSION IF NOT EXISTS citext;

-- uuidv7(): RFC 9562 UUID version 7 — millisecond-precision timestamp
-- in the leading 48 bits, then version + variant bits, then 74 random bits.
-- Time-sortable, index-friendly, no client coordination needed.
CREATE OR REPLACE FUNCTION uuidv7() RETURNS uuid AS $$
DECLARE
    unix_ts_ms bytea;
    uuid_bytes bytea;
BEGIN
    -- 6-byte big-endian millisecond timestamp
    unix_ts_ms := substring(
        int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint)
        FROM 3
    );

    -- 6 bytes timestamp || 10 bytes randomness
    uuid_bytes := unix_ts_ms || gen_random_bytes(10);

    -- Set version (0111xxxx = 112) in byte 6
    uuid_bytes := set_byte(
        uuid_bytes,
        6,
        (112 | (get_byte(uuid_bytes, 6) & 15))
    );

    -- Set variant (10xxxxxx = 128) in byte 8
    uuid_bytes := set_byte(
        uuid_bytes,
        8,
        (128 | (get_byte(uuid_bytes, 8) & 63))
    );

    RETURN encode(uuid_bytes, 'hex')::uuid;
END;
$$ LANGUAGE plpgsql VOLATILE;

-- touch_updated_at(): trigger function to bump updated_at on UPDATE.
-- Attached to each table that has updated_at.
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- users: canonical user record.
-- Credentials, MFA, sessions, etc. live in separate tables added later.
CREATE TABLE users (
    id              uuid        PRIMARY KEY DEFAULT uuidv7(),
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

-- One active (non-deleted) user per email. Permits the same address to be
-- reused after a hard-deletion-by-tombstone scenario down the road.
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

COMMIT;
