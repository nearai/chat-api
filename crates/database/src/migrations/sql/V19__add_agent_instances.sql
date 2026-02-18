-- Generic agent instances table (supports various agent types)
-- Supports both openclaw and ironclaw agent types
CREATE TABLE agent_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instance_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'openclaw', -- openclaw, ironclaw
    public_ssh_key TEXT,
    instance_url TEXT,
    instance_token TEXT,
    gateway_port INTEGER,
    dashboard_url TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- soft-delete support: active, stopped, deleted, provisioning, error
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT agent_instances_status_check CHECK (status IN ('active', 'stopped', 'deleted', 'provisioning', 'error')),
    CONSTRAINT agent_instances_type_check CHECK (type IN ('openclaw', 'ironclaw'))
);

CREATE INDEX idx_agent_instances_user_id ON agent_instances(user_id);
-- NOTE: idx_agent_instances_instance_id removed - UNIQUE constraint on instance_id already creates an index
CREATE INDEX idx_agent_instances_created_at_desc ON agent_instances(created_at DESC);

-- Trigger for updated_at
CREATE TRIGGER update_agent_instances_updated_at
    BEFORE UPDATE ON agent_instances
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Agent API keys table
-- API keys are stored as SHA-256 hashes; plaintext is returned only on creation
-- instance_id can be NULL for "unbound" keys (pre-deployment keys without instance)
CREATE TABLE agent_api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    instance_id UUID REFERENCES agent_instances(id) ON DELETE CASCADE,
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
-- NOTE: api_key_id uses SET NULL instead of CASCADE to preserve audit trail when API keys are revoked
CREATE TABLE agent_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instance_id UUID NOT NULL REFERENCES agent_instances(id) ON DELETE RESTRICT,
    api_key_id UUID REFERENCES agent_api_keys(id) ON DELETE SET NULL,
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
-- Uses RESTRICT to preserve balance records when instances are soft-deleted
CREATE TABLE agent_balance (
    instance_id UUID PRIMARY KEY REFERENCES agent_instances(id) ON DELETE RESTRICT,
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

-- Atomic instance creation with limit check to prevent race conditions
-- This function locks the user's rows, checks the limit, and creates an instance atomically
-- Returns the created instance or empty result set if limit would be exceeded
CREATE OR REPLACE FUNCTION create_instance_with_limit(
    p_user_id UUID,
    p_instance_id VARCHAR(255),
    p_name VARCHAR(255),
    p_type VARCHAR(50),
    p_public_ssh_key TEXT,
    p_instance_url TEXT,
    p_instance_token TEXT,
    p_gateway_port INTEGER,
    p_dashboard_url TEXT,
    p_max_allowed BIGINT
)
RETURNS TABLE(
    id UUID,
    user_id UUID,
    instance_id VARCHAR(255),
    name VARCHAR(255),
    type VARCHAR(50),
    public_ssh_key TEXT,
    instance_url TEXT,
    instance_token TEXT,
    gateway_port INTEGER,
    dashboard_url TEXT,
    status VARCHAR(20),
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
) AS $$
DECLARE
    v_current_count BIGINT;
    v_new_instance agent_instances;
BEGIN
    -- Lock the user's row to prevent concurrent modifications
    PERFORM 1 FROM users WHERE id = p_user_id FOR UPDATE;

    -- Count current instances for this user (excluding soft-deleted)
    SELECT COUNT(*) INTO v_current_count FROM agent_instances
    WHERE user_id = p_user_id AND status != 'deleted';

    -- If limit would be exceeded, return no rows
    IF v_current_count >= p_max_allowed THEN
        RETURN;
    END IF;

    -- Limit check passed, create the instance
    INSERT INTO agent_instances (
        user_id, instance_id, name, type, public_ssh_key, instance_url,
        instance_token, gateway_port, dashboard_url
    ) VALUES (
        p_user_id, p_instance_id, p_name, p_type, p_public_ssh_key, p_instance_url,
        p_instance_token, p_gateway_port, p_dashboard_url
    ) RETURNING * INTO v_new_instance;

    -- Return the created instance
    RETURN QUERY SELECT
        v_new_instance.id,
        v_new_instance.user_id,
        v_new_instance.instance_id,
        v_new_instance.name,
        v_new_instance.type,
        v_new_instance.public_ssh_key,
        v_new_instance.instance_url,
        v_new_instance.instance_token,
        v_new_instance.gateway_port,
        v_new_instance.dashboard_url,
        v_new_instance.status,
        v_new_instance.created_at,
        v_new_instance.updated_at;
END;
$$ LANGUAGE plpgsql;
