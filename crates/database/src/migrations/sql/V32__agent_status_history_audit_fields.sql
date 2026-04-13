-- Add explicit actor/reason audit fields for status history.
ALTER TABLE agent_instance_status_history
    ADD COLUMN IF NOT EXISTS changed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS change_reason TEXT;

-- We now write history rows explicitly from the repository with actor/reason context.
DROP TRIGGER IF EXISTS trg_agent_instance_status_change ON agent_instances;
DROP FUNCTION IF EXISTS record_agent_status_change();
