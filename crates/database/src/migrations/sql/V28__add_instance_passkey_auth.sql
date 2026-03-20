-- Add per-instance passkey authentication support to agent_instances table
-- Existing instances default to 'manager_token' auth method with NULL credentials
ALTER TABLE agent_instances
  ADD COLUMN auth_method VARCHAR(20) NOT NULL DEFAULT 'manager_token',
  ADD COLUMN auth_secret TEXT,
  ADD COLUMN backup_passphrase TEXT;

-- Ensure the new column values are valid
ALTER TABLE agent_instances
  ADD CONSTRAINT agent_instances_auth_method_check
  CHECK (auth_method IN ('manager_token', 'passkey'));

-- Create index for potential future queries on auth_method
CREATE INDEX idx_agent_instances_auth_method ON agent_instances(auth_method);
