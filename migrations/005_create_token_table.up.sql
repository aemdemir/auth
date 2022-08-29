CREATE TABLE IF NOT EXISTS token (
    user_id     BIGINT    NOT NULL,
    hash        BYTEA     NOT NULL,
    scope       TEXT      NOT NULL,
    revoked     BOOLEAN   NOT NULL DEFAULT false,
    expiry      TIMESTAMP(0) WITH TIME ZONE NOT NULL,
    payload     TEXT,
    created     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated     TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT  uq_token_hash    UNIQUE (hash),
    CONSTRAINT  fk_token_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT  check_scope      CHECK (scope IN ('auth', 'confirmation', 'email_verification', 'password_reset'))
);

CREATE OR REPLACE TRIGGER update_updated_timestamp BEFORE INSERT OR UPDATE ON token
    FOR EACH ROW EXECUTE FUNCTION update_updated_timestamp();