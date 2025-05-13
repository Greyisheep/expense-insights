-- 002_create_statements_table.down.sql

DROP TRIGGER IF EXISTS trigger_statements_updated_at ON statements;
-- The trigger function update_updated_at_column() is shared, so it's dropped with uploads table down migration.

DROP INDEX IF EXISTS idx_statements_created_at;
DROP INDEX IF EXISTS idx_statements_statement_date;
DROP INDEX IF EXISTS idx_statements_status;
DROP INDEX IF EXISTS idx_statements_upload_id;
DROP INDEX IF EXISTS idx_statements_user_id;

DROP TABLE IF EXISTS statements;

DROP TYPE IF EXISTS statement_status; 