-- 0003_cas.down.sql
BEGIN;

DROP TABLE IF EXISTS cas_tickets;
DROP TRIGGER IF EXISTS cas_services_touch_updated_at ON cas_services;
DROP TABLE IF EXISTS cas_services;

COMMIT;
