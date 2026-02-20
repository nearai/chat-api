-- Add agent-specific columns and JSONB details to user_usage_event
ALTER TABLE user_usage_event
    ADD COLUMN instance_id UUID REFERENCES agent_instances(id) ON DELETE RESTRICT,
    ADD COLUMN api_key_id  UUID REFERENCES agent_api_keys(id) ON DELETE SET NULL,
    ADD COLUMN details     JSONB;

-- Agent-specific indexes (partial — only agent rows)
CREATE INDEX idx_user_usage_event_instance_created
    ON user_usage_event(instance_id, created_at DESC)
    WHERE instance_id IS NOT NULL;

CREATE INDEX idx_user_usage_event_api_key
    ON user_usage_event(api_key_id)
    WHERE api_key_id IS NOT NULL;

-- Migrate existing agent_usage_log data into user_usage_event
INSERT INTO user_usage_event (
    user_id, metric_key, quantity, cost_nano_usd, model_id,
    instance_id, api_key_id, details, created_at
)
SELECT
    user_id,
    'llm.tokens',
    total_tokens,
    total_cost,
    model_id,
    instance_id,
    api_key_id,
    jsonb_build_object(
        'input_tokens', input_tokens,
        'output_tokens', output_tokens,
        'input_cost', input_cost,
        'output_cost', output_cost,
        'request_type', request_type
    ),
    created_at
FROM agent_usage_log;

-- Delete duplicate user_usage_event rows that were the "user side" of agent dual-writes.
-- These have same user_id, model_id, quantity=total_tokens, and close timestamps to an
-- agent_usage_log row, but no instance_id (since they were written before this migration).
DELETE FROM user_usage_event uue
WHERE uue.instance_id IS NULL
  AND uue.metric_key = 'llm.tokens'
  AND EXISTS (
      SELECT 1 FROM user_usage_event migrated
      WHERE migrated.instance_id IS NOT NULL
        AND migrated.user_id = uue.user_id
        AND migrated.model_id = uue.model_id
        AND migrated.quantity = uue.quantity
        AND migrated.created_at BETWEEN uue.created_at - INTERVAL '2 seconds'
                                     AND uue.created_at + INTERVAL '2 seconds'
  );
