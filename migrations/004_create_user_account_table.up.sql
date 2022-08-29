CREATE TABLE IF NOT EXISTS user_account (
    user_id          BIGINT       NOT NULL,
    provider_name    TEXT         NOT NULL,
    provider_user_id TEXT         NOT NULL,
    created          TIMESTAMP(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_ua_user_id_prv_name     UNIQUE (user_id, provider_name),
    CONSTRAINT uq_ua_prv_name_prv_user_id UNIQUE (provider_name, provider_user_id),
    CONSTRAINT fk_user_account_user_id    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT check_provider_name        CHECK (provider_name IN ('google', 'twitter'))
);