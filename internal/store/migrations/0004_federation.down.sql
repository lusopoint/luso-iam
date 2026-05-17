-- 0004_federation.down.sql
BEGIN;

DROP TRIGGER IF EXISTS user_identities_touch_updated_at ON user_identities;
DROP TABLE IF EXISTS user_identities;

COMMIT;
