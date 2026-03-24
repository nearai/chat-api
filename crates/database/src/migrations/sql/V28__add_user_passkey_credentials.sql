-- Add per-user passkey credentials for agent instances
-- Users register once and reuse credentials for all their instances
CREATE TABLE user_passkey_credentials (
  id SERIAL PRIMARY KEY,
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  auth_secret TEXT NOT NULL,
  backup_passphrase TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create index for user lookups
CREATE INDEX idx_user_passkey_credentials_user_id ON user_passkey_credentials(user_id);
