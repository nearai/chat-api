-- Support pre-deployment API keys (keys created before instance is known)
-- This allows:
-- 1. Create unbound key before deploying an instance
-- 2. Deploy agent with the key in environment
-- 3. Agent registers itself and binds the key to its instance_id

-- Make instance_id nullable (keys can exist without an instance)
ALTER TABLE agent_api_keys
ALTER COLUMN instance_id DROP NOT NULL;

-- Add a helper function to find unbound keys by hash
-- Unbound keys can be used for initial agent registration/setup
CREATE INDEX IF NOT EXISTS idx_agent_api_keys_instance_id_null
ON agent_api_keys(instance_id) WHERE instance_id IS NULL;

-- Add comment to document the unbound key feature
COMMENT ON COLUMN agent_api_keys.instance_id IS
  'Instance ID this key belongs to. NULL for unbound keys that will be bound on first use.';
