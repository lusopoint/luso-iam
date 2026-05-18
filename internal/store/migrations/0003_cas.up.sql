-- 0003_cas.up.sql
-- CAS service registry and ephemeral service tickets.

BEGIN;

-- cas_services: registered CAS service URLs. The login flow validates
-- that the `service` query parameter matches one of these entries.
--
-- Matching: simple prefix match using SQL LIKE, with '*' wildcards in
-- service_url_pattern converted to '%'. We pre-compute the LIKE pattern
-- at insert time (stored in `match_pattern`) so lookups are a single
-- indexed predicate.
CREATE TABLE cas_services (
    id                   uuid        PRIMARY KEY DEFAULT uuidv7(),
    name                 text        NOT NULL,
    -- Human-authored pattern with '*' wildcards, e.g. 'https://app.example.com/*'
    service_url_pattern  text        NOT NULL,
    -- SQL LIKE pattern derived from service_url_pattern at write time.
    match_pattern        text        NOT NULL,
    description          text        NULL,
    -- Attribute release policy (used by CAS 3.0 / SAML 1.1 validation).
    -- Empty array means only the username is released.
    released_attributes  text[]      NOT NULL DEFAULT '{}',
    enabled              boolean     NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    deleted_at           timestamptz NULL
);

CREATE UNIQUE INDEX cas_services_pattern_active_uq
    ON cas_services (service_url_pattern)
    WHERE deleted_at IS NULL;

CREATE INDEX cas_services_match_idx
    ON cas_services (match_pattern)
    WHERE deleted_at IS NULL AND enabled;

CREATE TRIGGER cas_services_touch_updated_at
    BEFORE UPDATE ON cas_services
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- cas_tickets: ephemeral service tickets issued by /cas/login and
-- consumed by /cas/serviceValidate. Single-use, short-lived (~60s).
--
-- The ticket itself is the primary key — a server-generated random
-- string with the "ST-" prefix as required by the CAS spec.
CREATE TABLE cas_tickets (
    id           text        PRIMARY KEY,  -- e.g. "ST-<32 hex chars>"
    session_id   uuid        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    service_url  text        NOT NULL,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz NULL,
    renew        boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX cas_tickets_expires_at_idx
    ON cas_tickets (expires_at)
    WHERE consumed_at IS NULL;

COMMIT;
