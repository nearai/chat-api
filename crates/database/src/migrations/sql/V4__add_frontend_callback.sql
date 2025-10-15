-- Add frontend_callback column to oauth_states table
-- This stores the frontend URL to redirect to after OAuth completion
ALTER TABLE oauth_states 
ADD COLUMN frontend_callback TEXT;

