ALTER TABLE sessions DROP COLUMN IF EXISTS amr;
ALTER TABLE sessions DROP COLUMN IF EXISTS acr;

DROP TABLE IF EXISTS user_backup_codes;
DROP TRIGGER IF EXISTS user_mfa_methods_touch_updated_at ON user_mfa_methods;
DROP TABLE IF EXISTS user_mfa_methods;

