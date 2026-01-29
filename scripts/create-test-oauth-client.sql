-- Create a test OAuth client for local development
-- Run with: docker compose exec -T postgres psql -U postgres -d chat_api < scripts/create-test-oauth-client.sql

-- First, ensure we have a test user
INSERT INTO users (id, email, name, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'test@example.com',
    'Test User',
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Create a test project
INSERT INTO projects (id, owner_id, name, description, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'Test OAuth App',
    'A test OAuth application for development',
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;

-- Create the OAuth client (public client, no secret needed)
INSERT INTO oauth_clients (
    id,
    project_id,
    client_id,
    client_secret_hash,
    client_type,
    redirect_uris,
    allowed_scopes,
    created_at
) VALUES (
    '00000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000002',
    'test-client',
    NULL,  -- Public client, no secret
    'public',
    ARRAY['http://localhost:3001/oauth-test.html', 'http://localhost:3000/callback', 'http://127.0.0.1:3001/oauth-test.html'],
    ARRAY['memory.read', 'memory.write', 'memory.read.all'],
    NOW()
) ON CONFLICT (client_id) DO UPDATE SET
    redirect_uris = EXCLUDED.redirect_uris,
    allowed_scopes = EXCLUDED.allowed_scopes;

-- Output the created client
SELECT
    c.client_id,
    c.client_type,
    c.redirect_uris,
    c.allowed_scopes,
    p.name as project_name
FROM oauth_clients c
JOIN projects p ON c.project_id = p.id
WHERE c.client_id = 'test-client';
