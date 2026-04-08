WITH recalculated AS (
    SELECT
        ab.instance_id,
        COALESCE(
            SUM(u.quantity) FILTER (WHERE u.metric_key = 'llm.tokens'),
            0
        )::BIGINT AS total_tokens
    FROM agent_balance ab
    LEFT JOIN user_usage_event u ON u.instance_id = ab.instance_id
    GROUP BY ab.instance_id
)
UPDATE agent_balance AS ab
SET total_tokens = recalculated.total_tokens
FROM recalculated
WHERE ab.instance_id = recalculated.instance_id
  AND ab.total_tokens IS DISTINCT FROM recalculated.total_tokens;
