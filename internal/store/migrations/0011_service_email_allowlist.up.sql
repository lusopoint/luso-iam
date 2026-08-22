-- require_allowlist is an EXPLICIT opt-in flag on each service
ALTER TABLE oidc_clients ADD COLUMN require_allowlist boolean NOT NULL DEFAULT false;
ALTER TABLE cas_services ADD COLUMN require_allowlist boolean NOT NULL DEFAULT false;

-- service_email_allowlist holds the permitted emails per service
-- the table is polymorphic over the two service kinds because their ids
-- have different types: an OIDC client id is a text string, a CAS service id is a uuid
-- we store both as text in service_id and discriminate with service_type
-- email is citext so membership checks are case-insensitive and line up with users.email (also citext)
CREATE TABLE service_email_allowlist (
    id           uuid        PRIMARY KEY DEFAULT uuid(),
    service_type text        NOT NULL CHECK (service_type IN ('oidc', 'cas')),
    service_id   text        NOT NULL,
    email        citext      NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (service_type, service_id, email)
);

-- listing + membership both filter on (service_type, service_id)
-- the unique index above already serves exact-email lookups
CREATE INDEX service_email_allowlist_service_idx ON service_email_allowlist (service_type, service_id);

