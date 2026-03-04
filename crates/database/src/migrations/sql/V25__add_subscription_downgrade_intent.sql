-- Add fields for deferred downgrade intent tracking on subscriptions.
ALTER TABLE subscriptions
    ADD COLUMN pending_downgrade_target_price_id VARCHAR(255),
    ADD COLUMN pending_downgrade_from_price_id VARCHAR(255),
    ADD COLUMN pending_downgrade_expected_period_end TIMESTAMPTZ,
    ADD COLUMN pending_downgrade_status VARCHAR(32),
    ADD COLUMN pending_downgrade_updated_at TIMESTAMPTZ;

ALTER TABLE subscriptions
    ADD CONSTRAINT chk_pending_downgrade_status
        CHECK (
            pending_downgrade_status IS NULL
            OR pending_downgrade_status IN ('pending', 'applied', 'missed', 'unsatisfy')
        );

CREATE INDEX idx_subscriptions_pending_downgrade_status
    ON subscriptions (pending_downgrade_status);
