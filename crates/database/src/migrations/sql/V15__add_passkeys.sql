-- Passkey tables for WebAuthn support
CREATE TABLE passkeys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    user_handle BYTEA,
    algorithm VARCHAR(32) NOT NULL,
    friendly_name TEXT,
    transports TEXT[],
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);

CREATE TRIGGER update_passkeys_updated_at
    BEFORE UPDATE ON passkeys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE passkey_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge TEXT NOT NULL UNIQUE,
    purpose VARCHAR(32) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    metadata JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
