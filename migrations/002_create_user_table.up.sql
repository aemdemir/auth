CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL    NOT NULL,
    username      VARCHAR(15)  NOT NULL,
    name          VARCHAR(64),
    active        BOOLEAN      NOT NULL DEFAULT true,
    version       INTEGER      NOT NULL DEFAULT 1,
    created       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    password_hash BYTEA,
    CONSTRAINT    uq_user_username UNIQUE (username),
    PRIMARY KEY   (id)
);

CREATE OR REPLACE TRIGGER update_updated_timestamp BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_timestamp();