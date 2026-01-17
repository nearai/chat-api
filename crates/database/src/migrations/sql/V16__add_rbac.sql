-- Permissions table with module:action:scope pattern
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    module VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_permissions_module ON permissions(module);
CREATE INDEX idx_permissions_code ON permissions(code);

-- Roles table (system + custom org-scoped roles)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- System roles have NULL organization_id, custom roles are scoped to org
CREATE UNIQUE INDEX idx_roles_system_name ON roles(name) WHERE organization_id IS NULL AND is_system = TRUE;
CREATE UNIQUE INDEX idx_roles_org_name ON roles(organization_id, name) WHERE organization_id IS NOT NULL;
CREATE INDEX idx_roles_organization_id ON roles(organization_id);

-- Trigger for roles updated_at
CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Role permissions junction table
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);

-- User roles assignment table with org/workspace scope
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- A user can only have one assignment of a role per scope
    UNIQUE(user_id, role_id, organization_id, workspace_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_organization_id ON user_roles(organization_id);
CREATE INDEX idx_user_roles_workspace_id ON user_roles(workspace_id);

-- Seed system permissions
INSERT INTO permissions (code, name, description, module, action) VALUES
-- Organization permissions
('organizations:read:own', 'View Own Organization', 'View organization details', 'organizations', 'read'),
('organizations:update:own', 'Update Own Organization', 'Update organization settings', 'organizations', 'update'),
('organizations:delete:own', 'Delete Own Organization', 'Delete organization', 'organizations', 'delete'),
('organizations:manage:members', 'Manage Organization Members', 'Invite, remove, and manage organization members', 'organizations', 'manage_members'),
('organizations:manage:billing', 'Manage Billing', 'View and manage organization billing', 'organizations', 'manage_billing'),

-- Workspace permissions
('workspaces:create', 'Create Workspace', 'Create new workspaces', 'workspaces', 'create'),
('workspaces:read:own', 'View Own Workspaces', 'View workspace details', 'workspaces', 'read'),
('workspaces:read:all', 'View All Workspaces', 'View all workspaces in organization', 'workspaces', 'read_all'),
('workspaces:update:own', 'Update Own Workspaces', 'Update workspace settings', 'workspaces', 'update'),
('workspaces:update:all', 'Update All Workspaces', 'Update any workspace in organization', 'workspaces', 'update_all'),
('workspaces:delete:own', 'Delete Own Workspaces', 'Delete workspaces you manage', 'workspaces', 'delete'),
('workspaces:delete:all', 'Delete All Workspaces', 'Delete any workspace in organization', 'workspaces', 'delete_all'),
('workspaces:manage:members', 'Manage Workspace Members', 'Add and remove workspace members', 'workspaces', 'manage_members'),

-- Conversation permissions
('conversations:create', 'Create Conversations', 'Create new conversations', 'conversations', 'create'),
('conversations:read:own', 'View Own Conversations', 'View own conversations', 'conversations', 'read'),
('conversations:read:workspace', 'View Workspace Conversations', 'View all workspace conversations', 'conversations', 'read_workspace'),
('conversations:update:own', 'Update Own Conversations', 'Update own conversations', 'conversations', 'update'),
('conversations:delete:own', 'Delete Own Conversations', 'Delete own conversations', 'conversations', 'delete'),
('conversations:delete:workspace', 'Delete Workspace Conversations', 'Delete any workspace conversation', 'conversations', 'delete_workspace'),

-- File permissions
('files:create', 'Upload Files', 'Upload files', 'files', 'create'),
('files:read:own', 'View Own Files', 'View own files', 'files', 'read'),
('files:read:workspace', 'View Workspace Files', 'View all workspace files', 'files', 'read_workspace'),
('files:delete:own', 'Delete Own Files', 'Delete own files', 'files', 'delete'),
('files:delete:workspace', 'Delete Workspace Files', 'Delete any workspace file', 'files', 'delete_workspace'),

-- User management permissions
('users:read:org', 'View Organization Users', 'View users in organization', 'users', 'read'),
('users:invite', 'Invite Users', 'Invite new users to organization', 'users', 'invite'),
('users:update:roles', 'Update User Roles', 'Assign and update user roles', 'users', 'update_roles'),
('users:remove', 'Remove Users', 'Remove users from organization', 'users', 'remove'),

-- Role management permissions
('roles:read', 'View Roles', 'View roles and permissions', 'roles', 'read'),
('roles:create', 'Create Roles', 'Create custom roles', 'roles', 'create'),
('roles:update', 'Update Roles', 'Update role permissions', 'roles', 'update'),
('roles:delete', 'Delete Roles', 'Delete custom roles', 'roles', 'delete'),

-- Settings permissions
('settings:read:org', 'View Organization Settings', 'View organization settings', 'settings', 'read'),
('settings:update:org', 'Update Organization Settings', 'Update organization settings', 'settings', 'update'),
('settings:read:saml', 'View SAML Configuration', 'View SAML SSO configuration', 'settings', 'read_saml'),
('settings:update:saml', 'Update SAML Configuration', 'Configure SAML SSO', 'settings', 'update_saml'),
('settings:read:domains', 'View Domain Configuration', 'View verified domains', 'settings', 'read_domains'),
('settings:update:domains', 'Update Domain Configuration', 'Add and verify domains', 'settings', 'update_domains'),

-- Audit permissions
('audit:read', 'View Audit Logs', 'View organization audit logs', 'audit', 'read'),
('audit:export', 'Export Audit Logs', 'Export audit logs', 'audit', 'export');

-- Seed system roles and their permissions
-- Organization Owner (full access)
INSERT INTO roles (name, description, is_system) VALUES
('org_owner', 'Organization Owner with full access', TRUE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'org_owner' AND r.is_system = TRUE;

-- Organization Admin (all except delete org and billing)
INSERT INTO roles (name, description, is_system) VALUES
('org_admin', 'Organization Administrator', TRUE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'org_admin' AND r.is_system = TRUE
AND p.code NOT IN ('organizations:delete:own', 'organizations:manage:billing');

-- Workspace Admin (full workspace access)
INSERT INTO roles (name, description, is_system) VALUES
('workspace_admin', 'Workspace Administrator', TRUE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'workspace_admin' AND r.is_system = TRUE
AND p.code IN (
    'workspaces:read:own', 'workspaces:update:own',
    'workspaces:manage:members',
    'conversations:create', 'conversations:read:own', 'conversations:read:workspace',
    'conversations:update:own', 'conversations:delete:own', 'conversations:delete:workspace',
    'files:create', 'files:read:own', 'files:read:workspace',
    'files:delete:own', 'files:delete:workspace',
    'users:read:org'
);

-- Workspace Member (standard access)
INSERT INTO roles (name, description, is_system) VALUES
('workspace_member', 'Workspace Member', TRUE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'workspace_member' AND r.is_system = TRUE
AND p.code IN (
    'workspaces:read:own',
    'conversations:create', 'conversations:read:own', 'conversations:update:own', 'conversations:delete:own',
    'files:create', 'files:read:own', 'files:delete:own'
);

-- Workspace Viewer (read-only access)
INSERT INTO roles (name, description, is_system) VALUES
('workspace_viewer', 'Workspace Viewer (read-only)', TRUE);

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'workspace_viewer' AND r.is_system = TRUE
AND p.code IN (
    'workspaces:read:own',
    'conversations:read:workspace',
    'files:read:workspace'
);

