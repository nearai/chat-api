CREATE TABLE aml_risk_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    flow VARCHAR(80) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    account_id TEXT NOT NULL,
    address_type VARCHAR(32) NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    score BIGINT,
    provider_report_id TEXT,
    checked_at TIMESTAMPTZ NOT NULL,
    reason TEXT,
    result JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_aml_risk_reports_user_id ON aml_risk_reports(user_id);
CREATE INDEX idx_aml_risk_reports_account_id ON aml_risk_reports(account_id);
CREATE INDEX idx_aml_risk_reports_checked_at ON aml_risk_reports(checked_at DESC);
CREATE INDEX idx_aml_risk_reports_active_account_id ON aml_risk_reports(account_id, checked_at DESC)
    WHERE active;

CREATE TRIGGER update_aml_risk_reports_updated_at
    BEFORE UPDATE ON aml_risk_reports
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TABLE aml_account_allowlist (
    account_id TEXT PRIMARY KEY,
    reason TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_aml_account_allowlist_created_at ON aml_account_allowlist(created_at DESC);
