-- 0005_oidc.down.sql
BEGIN;

DROP TABLE IF EXISTS oidc_refresh_tokens;
DROP TABLE IF EXISTS oidc_access_tokens;
DROP TABLE IF EXISTS oidc_auth_codes;
DROP TRIGGER IF EXISTS oidc_clients_touch_updated_at ON oidc_clients;
DROP TABLE IF EXISTS oidc_clients;

COMMIT;
