-- Generic agent instances table (supports openclaw, ironclaw, and future agent types)
-- Type column specifies the agent type: 'openclaw', 'ironclaw', etc.
CREATE TABLE agent_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instance_id VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL DEFAULT 'openclaw',
    name VARCHAR(255) NOT NULL,
    public_ssh_key TEXT,
    instance_url TEXT,
    instance_token TEXT,
    gateway_port INTEGER,
    dashboard_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_instances_user_id ON agent_instances(user_id);
CREATE INDEX idx_agent_instances_instance_id ON agent_instances(instance_id);
CREATE INDEX idx_agent_instances_type ON agent_instances(type);
CREATE INDEX idx_agent_instances_created_at_desc ON agent_instances(created_at DESC);
CREATE INDEX idx_agent_instances_user_type ON agent_instances(user_id, type);

-- Trigger for updated_at
CREATE TRIGGER update_agent_instances_updated_at
    BEFORE UPDATE ON agent_instances
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Agent API keys table
-- API keys are stored as SHA-256 hashes; plaintext is returned only on creation
CREATE TABLE agent_api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    instance_id UUID NOT NULL REFERENCES agent_instances(id) ON DELETE CASCADE,
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

CREATE INDEX idx_agent_api_keys_instance_id ON agent_api_keys(instance_id);
CREATE INDEX idx_agent_api_keys_user_id ON agent_api_keys(user_id);
CREATE INDEX idx_agent_api_keys_key_hash ON agent_api_keys(key_hash);
CREATE INDEX idx_agent_api_keys_is_active ON agent_api_keys(is_active);
CREATE INDEX idx_agent_api_keys_expires_at ON agent_api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- Trigger for updated_at
CREATE TRIGGER update_agent_api_keys_updated_at
    BEFORE UPDATE ON agent_api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Agent usage log table
-- All costs are stored in nano-dollars (scale 9): $1.00 = 1,000,000,000 nano-dollars
CREATE TABLE agent_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instance_id UUID NOT NULL REFERENCES agent_instances(id) ON DELETE CASCADE,
    api_key_id UUID NOT NULL REFERENCES agent_api_keys(id) ON DELETE CASCADE,
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

CREATE INDEX idx_agent_usage_log_user_id ON agent_usage_log(user_id);
CREATE INDEX idx_agent_usage_log_instance_id ON agent_usage_log(instance_id);
CREATE INDEX idx_agent_usage_log_api_key_id ON agent_usage_log(api_key_id);
CREATE INDEX idx_agent_usage_log_created_at_desc ON agent_usage_log(created_at DESC);
CREATE INDEX idx_agent_usage_log_user_created ON agent_usage_log(user_id, created_at DESC);
CREATE INDEX idx_agent_usage_log_instance_created ON agent_usage_log(instance_id, created_at DESC);

-- Agent instance balance table (cached aggregate)
-- All costs are stored in nano-dollars (scale 9): $1.00 = 1,000,000,000 nano-dollars
CREATE TABLE agent_balance (
    instance_id UUID PRIMARY KEY REFERENCES agent_instances(id) ON DELETE CASCADE,
    total_spent BIGINT NOT NULL DEFAULT 0,
    total_requests BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    last_usage_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_balance_total_spent_desc ON agent_balance(total_spent DESC);
CREATE INDEX idx_agent_balance_last_usage_at_desc ON agent_balance(last_usage_at DESC);

-- Trigger to auto-create balance entry when instance is created
CREATE OR REPLACE FUNCTION create_agent_balance()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO agent_balance (instance_id, updated_at)
    VALUES (NEW.id, NOW());
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER auto_create_agent_balance
    AFTER INSERT ON agent_instances
    FOR EACH ROW
    EXECUTE FUNCTION create_agent_balance();

-- Legacy view for backward compatibility with OpenClaw-specific code
CREATE VIEW openclaw_instances AS
SELECT id, user_id, instance_id, name, public_ssh_key, instance_url, instance_token, gateway_port, dashboard_url, created_at, updated_at
FROM agent_instances
WHERE type = 'openclaw';

CREATE VIEW openclaw_api_keys AS
SELECT ak.id, ak.instance_id, ak.user_id, ak.key_hash, ak.name, ak.spend_limit, ak.expires_at, ak.last_used_at, ak.is_active, ak.created_at, ak.updated_at
FROM agent_api_keys ak
INNER JOIN agent_instances ai ON ak.instance_id = ai.id
WHERE ai.type = 'openclaw';
