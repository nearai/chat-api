-- Per-period entitlement snapshots for variable House-of-Stake credit plans.
-- Stake values are text because yoctoNEAR u128 values exceed BIGINT.
CREATE TABLE house_of_stake_credit_entitlement_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subscription_id VARCHAR(255) NOT NULL REFERENCES subscriptions(subscription_id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    -- Current-period high-water stake already credited. This only increases within a period.
    credited_stake_yocto TEXT NOT NULL CHECK (credited_stake_yocto ~ '^[0-9]+$'),
    -- Latest effective stake observed on chain. This may decrease and is carried into the next period baseline.
    last_observed_stake_yocto TEXT NOT NULL CHECK (last_observed_stake_yocto ~ '^[0-9]+$'),
    credit_limit_nano_usd BIGINT NOT NULL CHECK (credit_limit_nano_usd >= 0),
    last_reconciled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (period_end > period_start)
);

CREATE UNIQUE INDEX idx_hos_credit_entitlement_period
    ON house_of_stake_credit_entitlement_snapshots (subscription_id, period_start, period_end);

CREATE INDEX idx_hos_credit_entitlement_user_period
    ON house_of_stake_credit_entitlement_snapshots (user_id, period_start, period_end);

CREATE TRIGGER update_hos_credit_entitlement_snapshots_updated_at
    BEFORE UPDATE ON house_of_stake_credit_entitlement_snapshots
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
