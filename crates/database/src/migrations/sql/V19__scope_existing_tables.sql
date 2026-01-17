-- Add workspace_id to conversations table
ALTER TABLE conversations
    ADD COLUMN workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL;

CREATE INDEX idx_conversations_workspace_id ON conversations(workspace_id);

-- Add workspace_id to files table
ALTER TABLE files
    ADD COLUMN workspace_id UUID REFERENCES workspaces(id) ON DELETE SET NULL;

CREATE INDEX idx_files_workspace_id ON files(workspace_id);

-- Data migration: Create personal organizations and workspaces for existing users
-- This migration creates a personal org for each existing user that doesn't have one

-- Step 1: Create personal organizations for existing users
DO $$
DECLARE
    user_record RECORD;
    new_org_id UUID;
    new_workspace_id UUID;
    org_slug TEXT;
    slug_counter INTEGER;
BEGIN
    FOR user_record IN
        SELECT id, email, name
        FROM users
        WHERE organization_id IS NULL
    LOOP
        -- Generate a unique slug from email or use a UUID-based one
        org_slug := LOWER(REGEXP_REPLACE(SPLIT_PART(user_record.email, '@', 1), '[^a-z0-9]', '-', 'g'));
        slug_counter := 0;

        -- Handle slug uniqueness
        WHILE EXISTS (SELECT 1 FROM organizations WHERE slug = org_slug || CASE WHEN slug_counter = 0 THEN '' ELSE '-' || slug_counter::TEXT END) LOOP
            slug_counter := slug_counter + 1;
        END LOOP;

        IF slug_counter > 0 THEN
            org_slug := org_slug || '-' || slug_counter::TEXT;
        END IF;

        -- Create personal organization
        INSERT INTO organizations (
            name,
            slug,
            display_name,
            plan_tier,
            settings,
            status
        ) VALUES (
            COALESCE(user_record.name, SPLIT_PART(user_record.email, '@', 1)) || '''s Organization',
            org_slug,
            COALESCE(user_record.name, SPLIT_PART(user_record.email, '@', 1)),
            'free',
            '{"personal": true}'::jsonb,
            'active'
        ) RETURNING id INTO new_org_id;

        -- Create default workspace
        INSERT INTO workspaces (
            organization_id,
            name,
            slug,
            description,
            is_default,
            status
        ) VALUES (
            new_org_id,
            'Default',
            'default',
            'Default workspace',
            TRUE,
            'active'
        ) RETURNING id INTO new_workspace_id;

        -- Update user with organization and role
        UPDATE users
        SET organization_id = new_org_id, org_role = 'owner'
        WHERE id = user_record.id;

        -- Create workspace membership
        INSERT INTO workspace_memberships (
            workspace_id,
            user_id,
            role,
            status
        ) VALUES (
            new_workspace_id,
            user_record.id,
            'admin',
            'active'
        );

        -- Assign org_owner role to user
        INSERT INTO user_roles (
            user_id,
            role_id,
            organization_id
        ) SELECT
            user_record.id,
            r.id,
            new_org_id
        FROM roles r
        WHERE r.name = 'org_owner' AND r.is_system = TRUE;

        -- Update user's conversations to belong to the default workspace
        UPDATE conversations
        SET workspace_id = new_workspace_id
        WHERE user_id = user_record.id AND workspace_id IS NULL;

        -- Update user's files to belong to the default workspace
        UPDATE files
        SET workspace_id = new_workspace_id
        WHERE user_id = user_record.id AND workspace_id IS NULL;

    END LOOP;
END $$;

