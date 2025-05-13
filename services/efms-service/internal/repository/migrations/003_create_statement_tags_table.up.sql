-- 003_create_statement_tags_table.up.sql

CREATE TABLE IF NOT EXISTS statement_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    statement_id UUID NOT NULL REFERENCES statements(submission_id) ON DELETE CASCADE,
    tag VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (statement_id, tag) -- Ensure a tag is unique per statement
);

CREATE INDEX IF NOT EXISTS idx_statement_tags_statement_id ON statement_tags(statement_id);
CREATE INDEX IF NOT EXISTS idx_statement_tags_tag ON statement_tags(tag); 