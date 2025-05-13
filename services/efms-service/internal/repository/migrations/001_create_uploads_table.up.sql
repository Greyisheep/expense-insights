-- 001_create_uploads_table.up.sql

CREATE TYPE upload_status AS ENUM (
    'pending',              -- Initial status after presign, before client uploads to S3
    'uploaded',             -- Client has successfully uploaded to S3, EFMS confirmed via event
    'statement_registered', -- /statements POST call made, linked to a statement record
    'error'                 -- An error occurred
);

CREATE TABLE IF NOT EXISTS uploads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL, -- Assuming this will be FK to a users table in another service, or just stores the ID
    file_name VARCHAR(255) NOT NULL,
    content_type VARCHAR(100) NOT NULL,
    status upload_status NOT NULL DEFAULT 'pending',
    storage_path VARCHAR(1024),          -- Path in S3/MinIO (e.g., user_id/upload_id/file_name)
    size_bytes BIGINT,
    error_message TEXT,
    presign_expiry TIMESTAMPTZ,       -- When the presigned URL expires
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    -- updated_by UUID, -- Consider if needed based on your main users table schema
);

CREATE INDEX IF NOT EXISTS idx_uploads_user_id ON uploads(user_id);
CREATE INDEX IF NOT EXISTS idx_uploads_status ON uploads(status);
CREATE INDEX IF NOT EXISTS idx_uploads_created_at ON uploads(created_at);

-- Trigger to update 'updated_at' column on every update
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER trigger_uploads_updated_at
BEFORE UPDATE ON uploads
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
