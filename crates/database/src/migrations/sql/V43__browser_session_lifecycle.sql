-- Session rows remain the revocation root for all access/refresh credentials.
CREATE TABLE browser_sessions (
    session_id UUID PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    client TEXT NOT NULL CHECK (client IN ('user', 'admin')),
    origin TEXT NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE browser_access_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES browser_sessions(session_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX browser_access_session ON browser_access_tokens(session_id);
CREATE TABLE browser_refresh_tokens (
    token_hash VARCHAR(64) PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES browser_sessions(session_id) ON DELETE CASCADE,
    consumed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX browser_refresh_session ON browser_refresh_tokens(session_id);
