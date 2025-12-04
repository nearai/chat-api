-- Used nonces table for NEAR authentication replay protection
CREATE TABLE near_used_nonces (
    nonce_hash VARCHAR(64) PRIMARY KEY,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for cleanup of old nonces
CREATE INDEX idx_near_used_nonces_used_at ON near_used_nonces(used_at);
