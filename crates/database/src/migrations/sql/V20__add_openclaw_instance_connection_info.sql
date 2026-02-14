-- Add OpenClaw instance connection information
-- instance_url: The base URL of the OpenClaw instance (e.g., https://instance.openclaw.ai)
-- instance_token: Bearer token for authenticating with the instance
-- gateway_port: The port for the gateway service (if applicable)
-- dashboard_url: URL to the instance's web dashboard

ALTER TABLE openclaw_instances
ADD COLUMN instance_url VARCHAR(1024),
ADD COLUMN instance_token TEXT,
ADD COLUMN gateway_port INTEGER,
ADD COLUMN dashboard_url VARCHAR(1024);

-- Index for instance URL lookups (used for API key auth via proxy)
CREATE INDEX idx_openclaw_instances_instance_url ON openclaw_instances(instance_url);
