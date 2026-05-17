-- 0001_init.down.sql

BEGIN;

DROP TRIGGER IF EXISTS users_touch_updated_at ON users;
DROP TABLE IF EXISTS users;

DROP FUNCTION IF EXISTS touch_updated_at();
DROP FUNCTION IF EXISTS uuidv7();

-- Extensions are intentionally not dropped — they may be in use by other
-- schemas in the same database.

COMMIT;
