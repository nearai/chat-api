CREATE INDEX idx_aml_risk_reports_created_at ON aml_risk_reports(created_at DESC);
CREATE INDEX idx_aml_risk_reports_active_account_id_created_at
    ON aml_risk_reports(account_id, created_at DESC, checked_at DESC)
    WHERE active;
