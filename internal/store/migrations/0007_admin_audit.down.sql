-- 0007_admin_audit.down.sql
BEGIN;

DROP TABLE IF EXISTS audit_log;

DROP INDEX IF EXISTS users_is_admin_idx;
ALTER TABLE users DROP COLUMN IF EXISTS is_admin;

COMMIT;
