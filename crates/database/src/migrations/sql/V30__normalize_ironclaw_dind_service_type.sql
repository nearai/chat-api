-- Normalize ironclaw-dind service type to ironclaw
-- After removing -dind suffix types, existing instances with ironclaw-dind
-- should be normalized to just ironclaw (which now deploys the ironclaw-dind image via IRONCLAW_DIND_IMAGE env var)
UPDATE agent_instances
SET type = 'ironclaw'
WHERE type = 'ironclaw-dind';
