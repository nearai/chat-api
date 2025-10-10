-- Add token_hash column to sessions table
ALTER TABLE sessions ADD COLUMN token_hash VARCHAR(64) NOT NULL DEFAULT '';

-- Create index on token_hash for fast lookups
CREATE UNIQUE INDEX idx_sessions_token_hash ON sessions(token_hash) WHERE token_hash != '';

-- Remove the default after adding the column (we'll generate proper tokens going forward)
ALTER TABLE sessions ALTER COLUMN token_hash DROP DEFAULT;

