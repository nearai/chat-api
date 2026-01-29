-- OAuth Server Enhancements for Authorization Code Flow
-- Adds pending authorization support and improves refresh token tracking

-- Add user_id/client_id to refresh tokens for direct lookup
-- This fixes the issue where refresh tokens only link via access_token_id,
-- which breaks when the access token expires and gets cleaned up
ALTER TABLE oauth_refresh_tokens
  ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS client_id VARCHAR(64);

-- Create index for refresh token lookups by user/client
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user ON oauth_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client ON oauth_refresh_tokens(client_id);

-- Pending authorizations for consent flow (short-lived, 10 min TTL)
-- These store the authorization request while the user reviews and approves consent
CREATE TABLE oauth_pending_authorizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(64) NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT[] NOT NULL,
    state TEXT,
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_pending_auth_expires ON oauth_pending_authorizations(expires_at);
CREATE INDEX idx_oauth_pending_auth_user ON oauth_pending_authorizations(user_id);
