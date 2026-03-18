ALTER TABLE user_usage_event
    DROP CONSTRAINT user_usage_event_metric_key_check;

ALTER TABLE user_usage_event
    ADD CONSTRAINT user_usage_event_metric_key_check
    CHECK (metric_key IN ('llm.tokens', 'image.generate', 'image.edit', 'service.web_search'));
