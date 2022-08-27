CREATE TABLE IF NOT EXISTS user (
    id            INT UNSIGNED AUTO_INCREMENT NOT NULL,
    username      VARCHAR(15)  NOT NULL,
    name          VARCHAR(64),
    active        BOOLEAN      NOT NULL DEFAULT true,
    version       INT          NOT NULL DEFAULT 1,
    created       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    password_hash BLOB,
    UNIQUE        `uq_user_username` (username),
    PRIMARY KEY   (id)
);
