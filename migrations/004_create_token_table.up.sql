CREATE TABLE IF NOT EXISTS token (
    user_id     INT UNSIGNED NOT NULL,
    hash        BINARY(32)   NOT NULL,
    scope       ENUM('auth', 'confirmation', 'email_verification', 'password_reset') NOT NULL,
    revoked     BOOLEAN      NOT NULL DEFAULT false,
    expiry      DATETIME     NOT NULL,
    payload     TEXT,
    created     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE      `uq_token_hash`    (hash),
    CONSTRAINT  `fk_token_user_id` FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
);
