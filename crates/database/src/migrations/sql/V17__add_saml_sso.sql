-- SAML IdP configurations per organization
CREATE TABLE saml_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- IdP metadata
    idp_entity_id VARCHAR(512) NOT NULL,
    idp_sso_url TEXT NOT NULL,
    idp_slo_url TEXT,
    idp_certificate TEXT NOT NULL,

    -- SP configuration
    sp_entity_id VARCHAR(512) NOT NULL,
    sp_acs_url TEXT NOT NULL,

    -- Attribute mapping (JSONB for flexibility)
    attribute_mapping JSONB NOT NULL DEFAULT '{
        "email": "email",
        "firstName": "firstName",
        "lastName": "lastName",
        "displayName": "displayName"
    }'::jsonb,

    -- JIT (Just-In-Time) provisioning settings
    jit_provisioning_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    jit_default_role VARCHAR(50) DEFAULT 'workspace_member',
    jit_default_workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL,

    -- Configuration status
    is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One SAML config per organization
    UNIQUE(organization_id)
);

CREATE INDEX idx_saml_configs_organization_id ON saml_configs(organization_id);
CREATE INDEX idx_saml_configs_idp_entity_id ON saml_configs(idp_entity_id);

-- Trigger for saml_configs updated_at
CREATE TRIGGER update_saml_configs_updated_at
    BEFORE UPDATE ON saml_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- SAML authentication sessions (for RelayState and SLO)
CREATE TABLE saml_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- SAML session identifiers
    name_id VARCHAR(512) NOT NULL,
    name_id_format VARCHAR(256),
    session_index VARCHAR(256),

    -- For Single Logout (SLO)
    idp_session_id VARCHAR(512),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    UNIQUE(session_id)
);

CREATE INDEX idx_saml_sessions_session_id ON saml_sessions(session_id);
CREATE INDEX idx_saml_sessions_organization_id ON saml_sessions(organization_id);
CREATE INDEX idx_saml_sessions_expires_at ON saml_sessions(expires_at);

-- SAML authentication state (CSRF protection like oauth_states)
CREATE TABLE saml_auth_states (
    id VARCHAR(255) PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    relay_state TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_saml_auth_states_created_at ON saml_auth_states(created_at);

-- Domain verifications for email domain claim
CREATE TABLE domain_verifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Domain being verified
    domain VARCHAR(255) NOT NULL,

    -- Verification method and token
    verification_method VARCHAR(50) NOT NULL DEFAULT 'dns_txt',
    verification_token VARCHAR(255) NOT NULL,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    verified_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Each domain can only be verified by one org
    UNIQUE(domain)
);

CREATE INDEX idx_domain_verifications_organization_id ON domain_verifications(organization_id);
CREATE INDEX idx_domain_verifications_domain ON domain_verifications(domain);
CREATE INDEX idx_domain_verifications_status ON domain_verifications(status);

-- Trigger for domain_verifications updated_at
CREATE TRIGGER update_domain_verifications_updated_at
    BEFORE UPDATE ON domain_verifications
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

