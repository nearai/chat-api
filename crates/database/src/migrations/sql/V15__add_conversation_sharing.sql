-- Conversation sharing groups
CREATE TABLE conversation_share_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(owner_user_id, name)
);

CREATE INDEX idx_conversation_share_groups_owner ON conversation_share_groups(owner_user_id);

CREATE TRIGGER update_conversation_share_groups_updated_at
    BEFORE UPDATE ON conversation_share_groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Conversation sharing group members
CREATE TABLE conversation_share_group_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID NOT NULL REFERENCES conversation_share_groups(id) ON DELETE CASCADE,
    member_type VARCHAR(20) NOT NULL CHECK (member_type IN ('email', 'near')),
    member_value VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(group_id, member_type, member_value)
);

CREATE INDEX idx_conversation_share_group_members_group ON conversation_share_group_members(group_id);
CREATE INDEX idx_conversation_share_group_members_value
    ON conversation_share_group_members(member_type, member_value);

-- Conversation shares
CREATE TABLE conversation_shares (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    conversation_id VARCHAR(255) NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_type VARCHAR(20) NOT NULL CHECK (share_type IN ('direct', 'group', 'organization', 'public')),
    permission VARCHAR(10) NOT NULL CHECK (permission IN ('read', 'write')),
    recipient_type VARCHAR(20),
    recipient_value VARCHAR(255),
    group_id UUID REFERENCES conversation_share_groups(id) ON DELETE CASCADE,
    org_email_pattern VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (share_type = 'direct' AND recipient_type IS NOT NULL AND recipient_value IS NOT NULL
            AND group_id IS NULL AND org_email_pattern IS NULL)
        OR
        (share_type = 'group' AND group_id IS NOT NULL
            AND recipient_type IS NULL AND recipient_value IS NULL
            AND org_email_pattern IS NULL)
        OR
        (share_type = 'organization' AND org_email_pattern IS NOT NULL
            AND recipient_type IS NULL AND recipient_value IS NULL
            AND group_id IS NULL)
        OR
        (share_type = 'public'
            AND recipient_type IS NULL AND recipient_value IS NULL
            AND group_id IS NULL AND org_email_pattern IS NULL)
    )
);

CREATE INDEX idx_conversation_shares_conversation ON conversation_shares(conversation_id);
CREATE INDEX idx_conversation_shares_owner ON conversation_shares(owner_user_id);
CREATE INDEX idx_conversation_shares_recipient
    ON conversation_shares(recipient_type, recipient_value);
CREATE INDEX idx_conversation_shares_group ON conversation_shares(group_id);
CREATE INDEX idx_conversation_shares_org_pattern ON conversation_shares(org_email_pattern);

CREATE TRIGGER update_conversation_shares_updated_at
    BEFORE UPDATE ON conversation_shares
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

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
