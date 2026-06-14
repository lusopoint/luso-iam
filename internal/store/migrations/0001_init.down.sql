DROP TRIGGER IF EXISTS users_touch_updated_at ON users;
DROP TABLE IF EXISTS users;

DROP FUNCTION IF EXISTS touch_updated_at();
DROP FUNCTION IF EXISTS uuidv7();
