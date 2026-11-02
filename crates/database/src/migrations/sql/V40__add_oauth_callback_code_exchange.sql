ALTER TABLE oauth_states
    ADD COLUMN frontend_response_mode TEXT NOT NULL DEFAULT 'token'
        CHECK (frontend_response_mode IN ('token', 'code')),
    ADD COLUMN frontend_code_challenge TEXT,
    ADD COLUMN frontend_state TEXT;

CREATE TABLE oauth_callback_codes (
    code_hash VARCHAR(64) PRIMARY KEY,
    session_id UUID NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    code_challenge VARCHAR(128) NOT NULL,
    is_new_user BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_oauth_callback_codes_expires_at
    ON oauth_callback_codes(expires_at);
