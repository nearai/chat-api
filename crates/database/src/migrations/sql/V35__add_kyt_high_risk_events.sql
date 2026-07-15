CREATE TABLE kyt_high_risk_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    flow VARCHAR(80) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    account_id TEXT NOT NULL,
    address_type VARCHAR(32) NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    score BIGINT,
    report_id TEXT,
    checked_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kyt_high_risk_events_user_id ON kyt_high_risk_events(user_id);
CREATE INDEX idx_kyt_high_risk_events_account_id ON kyt_high_risk_events(account_id);
CREATE INDEX idx_kyt_high_risk_events_created_at ON kyt_high_risk_events(created_at DESC);
