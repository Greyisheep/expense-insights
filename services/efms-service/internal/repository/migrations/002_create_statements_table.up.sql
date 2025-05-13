-- 002_create_statements_table.up.sql

CREATE TYPE statement_status AS ENUM (
    'pending_file_confirmation', -- Initial: /statements called, but file not yet confirmed by S3 event
    'processing',                -- File confirmed, processing (e.g., by ETL) has been initiated
    'completed',                 -- Processing finished successfully, insights might be available
    'failed',                    -- Processing failed
    'archived'                   -- Statement has been archived (soft delete)
);

CREATE TABLE IF NOT EXISTS statements (
    submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Renamed from id to match API spec
    user_id UUID NOT NULL,
    upload_id UUID NOT NULL REFERENCES uploads(id) ON DELETE RESTRICT, -- Foreign key to uploads
    description TEXT,
    statement_date DATE,      -- Date of the statement (e.g., end of month for a monthly statement)
    bank_name VARCHAR(255),
    status statement_status NOT NULL DEFAULT 'pending_file_confirmation',
    processing_progress INT DEFAULT 0, -- Optional progress percentage (0-100)
    error_message TEXT,
    insights_available BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by UUID, -- Uncommented
    CONSTRAINT fk_statements_updated_by FOREIGN KEY (updated_by) REFERENCES users(id) -- Added FK constraint
);

CREATE INDEX IF NOT EXISTS idx_statements_user_id ON statements(user_id);
CREATE INDEX IF NOT EXISTS idx_statements_upload_id ON statements(upload_id);
CREATE INDEX IF NOT EXISTS idx_statements_status ON statements(status);
CREATE INDEX IF NOT EXISTS idx_statements_statement_date ON statements(statement_date);
CREATE INDEX IF NOT EXISTS idx_statements_created_at ON statements(created_at);

-- Reusing the trigger function from the uploads migration for updated_at
CREATE TRIGGER trigger_statements_updated_at
BEFORE UPDATE ON statements
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
