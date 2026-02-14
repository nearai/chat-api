-- OpenClaw instances table
CREATE TABLE openclaw_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instance_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    public_ssh_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_openclaw_instances_user_id ON openclaw_instances(user_id);
CREATE INDEX idx_openclaw_instances_instance_id ON openclaw_instances(instance_id);
CREATE INDEX idx_openclaw_instances_created_at_desc ON openclaw_instances(created_at DESC);

-- Trigger for updated_at
CREATE TRIGGER update_openclaw_instances_updated_at
    BEFORE UPDATE ON openclaw_instances
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- OpenClaw API keys table
-- API keys are stored as SHA-256 hashes; plaintext is returned only on creation
CREATE TABLE openclaw_api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    instance_id UUID NOT NULL REFERENCES openclaw_instances(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    spend_limit BIGINT,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_openclaw_api_keys_instance_id ON openclaw_api_keys(instance_id);
CREATE INDEX idx_openclaw_api_keys_user_id ON openclaw_api_keys(user_id);
CREATE INDEX idx_openclaw_api_keys_key_hash ON openclaw_api_keys(key_hash);
CREATE INDEX idx_openclaw_api_keys_is_active ON openclaw_api_keys(is_active);
CREATE INDEX idx_openclaw_api_keys_expires_at ON openclaw_api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- Trigger for updated_at
CREATE TRIGGER update_openclaw_api_keys_updated_at
    BEFORE UPDATE ON openclaw_api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- User instance usage log table
-- All costs are stored in nano-dollars (scale 9): $1.00 = 1,000,000,000 nano-dollars
CREATE TABLE user_instance_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instance_id UUID NOT NULL REFERENCES openclaw_instances(id) ON DELETE CASCADE,
    api_key_id UUID NOT NULL REFERENCES openclaw_api_keys(id) ON DELETE CASCADE,
    input_tokens BIGINT NOT NULL,
    output_tokens BIGINT NOT NULL,
    total_tokens BIGINT NOT NULL,
    input_cost BIGINT NOT NULL,
    output_cost BIGINT NOT NULL,
    total_cost BIGINT NOT NULL,
    model_id VARCHAR(255) NOT NULL,
    request_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_instance_usage_log_user_id ON user_instance_usage_log(user_id);
CREATE INDEX idx_user_instance_usage_log_instance_id ON user_instance_usage_log(instance_id);
CREATE INDEX idx_user_instance_usage_log_api_key_id ON user_instance_usage_log(api_key_id);
CREATE INDEX idx_user_instance_usage_log_created_at_desc ON user_instance_usage_log(created_at DESC);
CREATE INDEX idx_user_instance_usage_log_user_created ON user_instance_usage_log(user_id, created_at DESC);
CREATE INDEX idx_user_instance_usage_log_instance_created ON user_instance_usage_log(instance_id, created_at DESC);

-- User instance balance table (cached aggregate)
-- All costs are stored in nano-dollars (scale 9): $1.00 = 1,000,000,000 nano-dollars
CREATE TABLE user_instance_balance (
    instance_id UUID PRIMARY KEY REFERENCES openclaw_instances(id) ON DELETE CASCADE,
    total_spent BIGINT NOT NULL DEFAULT 0,
    total_requests BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    last_usage_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_instance_balance_total_spent_desc ON user_instance_balance(total_spent DESC);
CREATE INDEX idx_user_instance_balance_last_usage_at_desc ON user_instance_balance(last_usage_at DESC);

-- Trigger to auto-create balance entry when instance is created
CREATE OR REPLACE FUNCTION create_instance_balance()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO user_instance_balance (instance_id, updated_at)
    VALUES (NEW.id, NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER auto_create_instance_balance
    AFTER INSERT ON openclaw_instances
    FOR EACH ROW
    EXECUTE FUNCTION create_instance_balance();
