-- Audit table for tracking agent instance status changes
CREATE TABLE agent_instance_status_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    instance_id UUID NOT NULL REFERENCES agent_instances(id) ON DELETE CASCADE,
    old_status VARCHAR(20) NOT NULL,
    new_status VARCHAR(20) NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_status_history_instance_changed
    ON agent_instance_status_history(instance_id, changed_at DESC);

-- Index for BI queries that filter/join on agent_instances.type
CREATE INDEX idx_agent_instances_type ON agent_instances(type);

-- Trigger function to record status changes automatically
CREATE OR REPLACE FUNCTION record_agent_status_change()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO agent_instance_status_history (instance_id, old_status, new_status, changed_at)
        VALUES (NEW.id, OLD.status, NEW.status, NOW());
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agent_instance_status_change
    AFTER UPDATE ON agent_instances
    FOR EACH ROW
    EXECUTE FUNCTION record_agent_status_change();
