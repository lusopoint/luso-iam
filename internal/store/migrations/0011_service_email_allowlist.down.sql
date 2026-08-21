DROP TABLE IF EXISTS service_email_allowlist;
ALTER TABLE cas_services DROP COLUMN IF EXISTS require_allowlist;
ALTER TABLE oidc_clients DROP COLUMN IF EXISTS require_allowlist;

