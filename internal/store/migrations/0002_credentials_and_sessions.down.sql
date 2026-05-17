-- 0002_credentials_and_sessions.down.sql
BEGIN;

DROP TABLE IF EXISTS sessions;
DROP TRIGGER IF EXISTS user_credentials_touch_updated_at ON user_credentials;
DROP TABLE IF EXISTS user_credentials;

COMMIT;
