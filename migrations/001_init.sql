-- Migration MySQL untuk Laragon (Amanah Auth) - Fixed Version

CREATE TABLE users (
    id                    VARCHAR(36)  PRIMARY KEY,
    full_name             VARCHAR(100) NOT NULL,
    username              VARCHAR(30)  UNIQUE,
    email                 VARCHAR(254) NOT NULL UNIQUE,
    phone                 VARCHAR(16)  NOT NULL UNIQUE,
    password_hash         VARCHAR(100) NOT NULL,
    email_verified_at     DATETIME,
    phone_verified_at     DATETIME,
    status                ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    failed_login_attempts SMALLINT     NOT NULL DEFAULT 0,
    locked_until          DATETIME,
    created_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE otp_codes (
    id           VARCHAR(36)  PRIMARY KEY,
    user_id      VARCHAR(36),
    channel      ENUM('whatsapp', 'email') NOT NULL,
    destination  VARCHAR(254) NOT NULL,
    purpose      ENUM('login', 'password_reset') NOT NULL,
    code_hash    CHAR(64)     NOT NULL,
    attempts     SMALLINT     NOT NULL DEFAULT 0,
    max_attempts SMALLINT     NOT NULL DEFAULT 5,
    expires_at   DATETIME     NOT NULL,
    verified_at  DATETIME,
    consumed_at  DATETIME,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE refresh_tokens (
    id         VARCHAR(36)  PRIMARY KEY,
    user_id    VARCHAR(36)  NOT NULL,
    token_hash CHAR(64)     NOT NULL UNIQUE,
    expires_at DATETIME     NOT NULL,
    revoked_at DATETIME,
    user_agent VARCHAR(255) NOT NULL DEFAULT '',
    ip_address VARCHAR(45)  NOT NULL DEFAULT '',
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexing untuk mempercepat query lookup & verifikasi OTP
CREATE INDEX idx_otp_lookup ON otp_codes (destination, purpose, created_at DESC);
CREATE INDEX idx_otp_user ON otp_codes (user_id);
CREATE INDEX idx_refresh_user_live ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_expires ON refresh_tokens (expires_at);