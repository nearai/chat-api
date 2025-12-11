-- Create model_settings table
-- This table stores admin-level model settings per model as JSONB to allow flexible schema evolution
CREATE TABLE model_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id TEXT NOT NULL UNIQUE,
    content JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger for updating updated_at timestamp
CREATE TRIGGER update_model_settings_updated_at
    BEFORE UPDATE ON model_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

