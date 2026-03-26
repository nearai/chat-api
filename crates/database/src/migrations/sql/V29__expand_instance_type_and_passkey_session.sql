-- Expand agent_instances type constraint to include ironclaw-dind
-- The code supports three service types: openclaw, ironclaw, ironclaw-dind
-- but the constraint only allowed openclaw and ironclaw
ALTER TABLE agent_instances
  DROP CONSTRAINT agent_instances_type_check;

ALTER TABLE agent_instances
  ADD CONSTRAINT agent_instances_type_check CHECK (type IN ('openclaw', 'ironclaw', 'ironclaw-dind'));

-- Session token for passkey instances (from /auth/register; used for stop, start, delete, etc.)
ALTER TABLE agent_instances
  ADD COLUMN auth_session_token TEXT;

CREATE INDEX idx_agent_instances_auth_session_token ON agent_instances(auth_session_token)
  WHERE auth_session_token IS NOT NULL;
