-- Normalize service types to canonical forms: ironclaw-dind → ironclaw, openclaw-dind → openclaw
-- After removing -dind suffix types, existing instances should use canonical names.
-- - ironclaw-dind → ironclaw (deploys ironclaw-dind image configured in system_configs AgentHostingConfig)
-- - openclaw-dind → openclaw (defensive normalization, though V29 constraint never allowed this)
UPDATE agent_instances
SET type = 'ironclaw'
WHERE type = 'ironclaw-dind';

UPDATE agent_instances
SET type = 'openclaw'
WHERE type = 'openclaw-dind';

-- Tighten constraint to only canonical types
-- V29 allowed ('openclaw', 'ironclaw', 'ironclaw-dind') but this migration normalizes all data
-- to canonical types, so enforce that constraint going forward.
ALTER TABLE agent_instances
  DROP CONSTRAINT agent_instances_type_check;

ALTER TABLE agent_instances
  ADD CONSTRAINT agent_instances_type_check CHECK (type IN ('openclaw', 'ironclaw'));
