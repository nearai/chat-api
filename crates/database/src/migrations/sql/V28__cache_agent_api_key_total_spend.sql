ALTER TABLE agent_api_keys
ADD COLUMN total_spent BIGINT NOT NULL DEFAULT 0;

UPDATE agent_api_keys ak
SET total_spent = usage.total_spent
FROM (
    SELECT api_key_id, COALESCE(SUM(COALESCE(cost_nano_usd, 0)), 0)::BIGINT AS total_spent
    FROM user_usage_event
    WHERE api_key_id IS NOT NULL
    GROUP BY api_key_id
) AS usage
WHERE ak.id = usage.api_key_id;
