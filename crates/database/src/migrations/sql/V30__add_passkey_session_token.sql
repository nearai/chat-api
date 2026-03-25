-- Add session token column for passkey instances
-- This token is returned from /auth/register and used for all instance operations (stop, start, delete, etc)
ALTER TABLE agent_instances
  ADD COLUMN auth_session_token TEXT;

-- Create index for lookups if needed
CREATE INDEX idx_agent_instances_auth_session_token ON agent_instances(auth_session_token)
  WHERE auth_session_token IS NOT NULL;
