-- Organizations table (tenant boundary)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    logo_url TEXT,
    plan_tier VARCHAR(50) NOT NULL DEFAULT 'free',
    billing_email VARCHAR(255),
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_status ON organizations(status) WHERE deleted_at IS NULL;

-- Trigger for organizations updated_at
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Workspaces table (data/execution boundary within an organization)
CREATE TABLE workspaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    UNIQUE(organization_id, slug)
);

CREATE INDEX idx_workspaces_organization_id ON workspaces(organization_id);
CREATE INDEX idx_workspaces_status ON workspaces(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_workspaces_is_default ON workspaces(organization_id, is_default) WHERE is_default = TRUE;

-- Trigger for workspaces updated_at
CREATE TRIGGER update_workspaces_updated_at
    BEFORE UPDATE ON workspaces
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Add organization membership to users
ALTER TABLE users
    ADD COLUMN organization_id UUID REFERENCES organizations(id),
    ADD COLUMN org_role VARCHAR(50) DEFAULT 'member';

CREATE INDEX idx_users_organization_id ON users(organization_id);

-- Workspace memberships table
CREATE TABLE workspace_memberships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(workspace_id, user_id)
);

CREATE INDEX idx_workspace_memberships_workspace_id ON workspace_memberships(workspace_id);
CREATE INDEX idx_workspace_memberships_user_id ON workspace_memberships(user_id);
CREATE INDEX idx_workspace_memberships_status ON workspace_memberships(status) WHERE status = 'active';

-- Trigger for workspace_memberships updated_at
CREATE TRIGGER update_workspace_memberships_updated_at
    BEFORE UPDATE ON workspace_memberships
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

