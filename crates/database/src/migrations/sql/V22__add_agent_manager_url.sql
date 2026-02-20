ALTER TABLE agent_instances ADD COLUMN agent_api_base_url TEXT;
CREATE INDEX idx_agent_instances_manager_url_status ON agent_instances (agent_api_base_url, status) WHERE status != 'deleted';
