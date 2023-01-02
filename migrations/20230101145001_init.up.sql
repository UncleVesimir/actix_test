-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE user (
    -- id, name, email, 
    id uuid PRIMARY KEY uuid_generate_v4(),
    handle VARCHAR NOT NULL,
    first_name VARCHAR,
    

)