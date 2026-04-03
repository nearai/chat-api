-- Normalize openclaw-dind service type to openclaw (symmetric with V30 / ironclaw)
-- No rows are expected (V29 constraint never allowed openclaw-dind), but this is
-- defensive to handle any edge cases.
UPDATE agent_instances
SET type = 'openclaw'
WHERE type = 'openclaw-dind';

-- Tighten constraint to only canonical types
-- V29 allowed ('openclaw', 'ironclaw', 'ironclaw-dind') but V30 cleaned ironclaw-dind data
-- and this migration cleans any openclaw-dind edge cases. Enforce canonical types only.
ALTER TABLE agent_instances
  DROP CONSTRAINT agent_instances_type_check;

ALTER TABLE agent_instances
  ADD CONSTRAINT agent_instances_type_check CHECK (type IN ('openclaw', 'ironclaw'));
