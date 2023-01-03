-- Add down migration script here
DROP TABLE IF EXISTS oauth_requests;
DROP TABLE IF EXISTS auth_accounts;
DROP TABLE IF EXISTS users;
DROP FUNCTION IF EXISTS update_last_updated_at_column;
DROP EXTENSION IF EXISTS "uuid-ossp";
