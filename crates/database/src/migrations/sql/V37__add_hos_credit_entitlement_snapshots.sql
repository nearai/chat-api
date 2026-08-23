CREATE TABLE house_of_stake_credit_entitlement_snapshots (
    subscription_id VARCHAR(255) NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    credited_stake_yocto TEXT NOT NULL CHECK (credited_stake_yocto ~ '^[0-9]+$'),
    last_observed_stake_yocto TEXT NOT NULL CHECK (last_observed_stake_yocto ~ '^[0-9]+$'),
    credit_limit_nano_usd BIGINT NOT NULL CHECK (credit_limit_nano_usd >= 0),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (subscription_id, period_start, period_end),
    CHECK (period_end > period_start)
);

CREATE INDEX idx_hos_credit_entitlement_subscription
    ON house_of_stake_credit_entitlement_snapshots (subscription_id, period_end DESC);
