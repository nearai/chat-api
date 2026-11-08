-- Absolute expiry already uses idx_sessions_expires_at. Index the other
-- cleanup predicate without changing the retained refresh replay records.
CREATE INDEX idx_browser_sessions_idle_expires_at ON browser_sessions(idle_expires_at);
