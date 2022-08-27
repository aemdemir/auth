CREATE TABLE IF NOT EXISTS user_email (
    user_id       INT UNSIGNED NOT NULL,
    address       VARCHAR(255) NOT NULL,
    is_primary    BOOLEAN      NOT NULL,
    verified      BOOLEAN      NOT NULL DEFAULT false,
    created       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE        `uq_user_email_address` (address),
    CONSTRAINT    `fk_user_email_user_id` FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
);
