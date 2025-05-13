-- 001_create_uploads_table.down.sql

DROP TRIGGER IF EXISTS trigger_uploads_updated_at ON uploads;
DROP FUNCTION IF EXISTS update_updated_at_column();

DROP INDEX IF EXISTS idx_uploads_created_at;
DROP INDEX IF EXISTS idx_uploads_status;
DROP INDEX IF EXISTS idx_uploads_user_id;

DROP TABLE IF EXISTS uploads;

DROP TYPE IF EXISTS upload_status; 