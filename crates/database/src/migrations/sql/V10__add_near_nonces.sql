-- Used nonces table for NEAR authentication replay protection
CREATE TABLE near_used_nonces (
    nonce_hex VARCHAR(64) PRIMARY KEY CHECK (char_length(nonce_hex) = 64 AND nonce_hex ~ '^[0-9a-f]{64}$'),
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for cleanup of old nonces
CREATE INDEX idx_near_used_nonces_used_at ON near_used_nonces(used_at);
