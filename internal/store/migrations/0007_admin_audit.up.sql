-- users.is_admin: simple role
ALTER TABLE users ADD COLUMN is_admin boolean NOT NULL DEFAULT false;
CREATE INDEX users_is_admin_idx ON users (is_admin) WHERE is_admin;

--append-only event log
-- - no UPDATE / DELETE: events are immutable. Enforced by application
--   code (no audit_log update queries exist) and by convention, if we
--   ever need stronger guarantees, add a row-level rule denying both

-- - actor_id: is the user who CAUSED the event target_id is the user the
--   event is ABOUT, if different

-- - metadata is jsonb so each event_type can carry its own shape
--   without schema migrations; queries filter on top-level keys
CREATE TABLE audit_log (
    id          uuid        PRIMARY KEY DEFAULT uuid(),
    event_type  text        NOT NULL,
    actor_id    uuid        NULL REFERENCES users(id) ON DELETE SET NULL,
    target_id   uuid        NULL REFERENCES users(id) ON DELETE SET NULL,
    metadata    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ip_address  text        NULL,
    user_agent  text        NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_created_at_idx ON audit_log (created_at DESC);
CREATE INDEX audit_log_event_type_idx ON audit_log (event_type, created_at DESC);
CREATE INDEX audit_log_actor_idx      ON audit_log (actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_log_target_idx     ON audit_log (target_id, created_at DESC) WHERE target_id IS NOT NULL;
