-- Table for storing purchased token balance per user
CREATE TABLE purchased_tokens (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    balance BIGINT NOT NULL DEFAULT 0 CHECK (balance >= 0),
    total_purchased BIGINT NOT NULL DEFAULT 0 CHECK (total_purchased >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger for updating updated_at timestamp on purchased_tokens
CREATE TRIGGER update_purchased_tokens_updated_at
    BEFORE UPDATE ON purchased_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
