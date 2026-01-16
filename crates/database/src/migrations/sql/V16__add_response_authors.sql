-- Track which user authored each response in a conversation
-- This enables showing correct author names in shared conversations
CREATE TABLE response_authors (
    conversation_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id),
    author_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (conversation_id, response_id)
);

CREATE INDEX idx_response_authors_conversation ON response_authors(conversation_id);
