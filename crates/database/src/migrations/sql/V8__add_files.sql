-- Files table to track OpenAI files per user
CREATE TABLE files (
    id VARCHAR(255) PRIMARY KEY, -- OpenAI file ID (e.g., "file-abc123")
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bytes BIGINT NOT NULL, -- File size in bytes
    file_created_at BIGINT NOT NULL, -- Unix timestamp from OpenAI
    file_expires_at BIGINT, -- Unix timestamp (nullable)
    filename VARCHAR(255) NOT NULL, -- File name
    purpose VARCHAR(50) NOT NULL, -- File purpose (e.g., "assistants", "fine-tune")
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), -- Local created timestamp
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW() -- Local updated timestamp
);

CREATE INDEX idx_files_user_id ON files(user_id);
CREATE INDEX idx_files_file_created_at ON files(file_created_at DESC);
CREATE INDEX idx_files_updated_at ON files(updated_at DESC);
CREATE INDEX idx_files_purpose ON files(purpose);

-- Trigger for files table
CREATE TRIGGER update_files_updated_at
    BEFORE UPDATE ON files
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

