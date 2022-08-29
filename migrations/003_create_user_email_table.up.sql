CREATE TABLE IF NOT EXISTS user_email (
    user_id       BIGINT       NOT NULL,
    address       VARCHAR(255) NOT NULL,
    is_primary    BOOLEAN      NOT NULL,
    verified      BOOLEAN      NOT NULL DEFAULT false,
    created       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated       TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT    uq_user_email_address UNIQUE (address),
    CONSTRAINT    fk_user_email_user_id FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE OR REPLACE TRIGGER update_updated_timestamp BEFORE INSERT OR UPDATE ON user_email
    FOR EACH ROW EXECUTE FUNCTION update_updated_timestamp();