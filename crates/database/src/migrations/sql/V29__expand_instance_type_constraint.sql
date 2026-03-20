-- Expand agent_instances type constraint to include ironclaw-dind
-- The code supports three service types: openclaw, ironclaw, ironclaw-dind
-- but the constraint only allowed openclaw and ironclaw
ALTER TABLE agent_instances
  DROP CONSTRAINT agent_instances_type_check;

ALTER TABLE agent_instances
  ADD CONSTRAINT agent_instances_type_check CHECK (type IN ('openclaw', 'ironclaw', 'ironclaw-dind'));
