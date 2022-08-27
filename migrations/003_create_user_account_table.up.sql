CREATE TABLE IF NOT EXISTS user_account (
    user_id          INT UNSIGNED   NOT NULL,
    provider_name    ENUM('google', 'twitter') NOT NULL,
    provider_user_id VARCHAR(255)   NOT NULL,
    created          DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE     `uq_ua_user_id_provider_name` (user_id, provider_name),
    UNIQUE     `uq_ua_provider_name_provider_user_id` (provider_name, provider_user_id),
    CONSTRAINT `fk_user_account_user_id` FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
);
