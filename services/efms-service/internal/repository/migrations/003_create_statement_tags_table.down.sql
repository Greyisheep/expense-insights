-- 003_create_statement_tags_table.down.sql

DROP INDEX IF EXISTS idx_statement_tags_tag;
DROP INDEX IF EXISTS idx_statement_tags_statement_id;

DROP TABLE IF EXISTS statement_tags; 