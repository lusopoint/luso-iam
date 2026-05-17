-- 0007_admin_audit.up.sql
-- Admin role flag + append-only audit log.
--
-- These two were left out of the foundational migrations on purpose:
-- admin elevation is meaningful only once the admin API exists, and the
-- audit log structure is informed by what events the rest of the code
-- actually emits — by P5 we know which events matter.

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────
-- users.is_admin: simple role flag. Anything more elaborate (RBAC, group
-- memberships) is overkill for a single-tenant IAM with one privileged role.
-- Promotion is intentionally manual (SQL or the CLI helper) so the bootstrap
-- step is explicit and auditable.
-- ─────────────────────────────────────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN is_admin boolean NOT NULL DEFAULT false;

CREATE INDEX users_is_admin_idx ON users (is_admin) WHERE is_admin;

-- ─────────────────────────────────────────────────────────────────────────
-- audit_log: append-only event log.
--
-- Design notes:
--   * No UPDATE / DELETE — events are immutable. Enforced by application
--     code (no audit_log update queries exist) and by convention; if we
--     ever need stronger guarantees, add a row-level rule denying both.
--   * actor_id is the user who CAUSED the event (admin doing the action,
--     or the subject themselves logging in). target_id is the user the
--     event is ABOUT, if different.
--   * metadata is JSONB so each event_type can carry its own shape
--     without schema migrations; queries filter on top-level keys.
-- ─────────────────────────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id          uuid        PRIMARY KEY DEFAULT uuidv7(),
    event_type  text        NOT NULL,
    -- The user who initiated this event. NULL for system events
    -- (e.g. background token cleanup) and for failed-login attempts
    -- where we never confirmed who the user was.
    actor_id    uuid        NULL REFERENCES users(id) ON DELETE SET NULL,
    -- The user this event is ABOUT. NULL for events without a subject
    -- (e.g. client_created).
    target_id   uuid        NULL REFERENCES users(id) ON DELETE SET NULL,
    -- Free-form context for the event.
    metadata    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ip_address  text        NULL,
    user_agent  text        NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Reverse-chronological listing is by far the most common access pattern.
CREATE INDEX audit_log_created_at_idx ON audit_log (created_at DESC);
CREATE INDEX audit_log_event_type_idx ON audit_log (event_type, created_at DESC);
CREATE INDEX audit_log_actor_idx      ON audit_log (actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX audit_log_target_idx     ON audit_log (target_id, created_at DESC) WHERE target_id IS NOT NULL;

COMMIT;
