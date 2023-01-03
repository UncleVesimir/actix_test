-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE oauth_requests (
    pkce_challenge TEXT,
    pkce_verifier TEXT,
    csrf_state TEXT
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    first_name TEXT,
    last_name TEXT,
    created_at TIMESTAMP DEFAULT current_timestamp
);

CREATE TABLE auth_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    authorizer TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    created_at TIMESTAMP DEFAULT current_timestamp,
    last_updated_at TIMESTAMP DEFAULT current_timestamp,
    user_id UUID REFERENCES users(id)
);

CREATE OR REPLACE FUNCTION update_last_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.last_updated_at = now(); 
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_account_last_updated_at BEFORE UPDATE
    ON auth_accounts FOR EACH ROW EXECUTE PROCEDURE
    update_last_updated_at_column();
