-- Secure Vault - pocetna MySQL 8.0 sema
-- Skripta je bezbjedna za ponovno pokretanje: koristi IF NOT EXISTS.
-- Ne sadrzi stvarne korisnike, lozinke, kljuceve niti honeytoken podatke.

CREATE DATABASE IF NOT EXISTS secure_vault
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE secure_vault;

-- Organizacione sigurnosne politike kojima upravlja ADMIN.
CREATE TABLE IF NOT EXISTS security_policies (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    minimum_login_password_length SMALLINT UNSIGNED NOT NULL DEFAULT 12,
    minimum_master_password_length SMALLINT UNSIGNED NOT NULL DEFAULT 14,
    secret_rotation_days       SMALLINT UNSIGNED NOT NULL DEFAULT 90,
    access_token_lifetime_seconds INT UNSIGNED NOT NULL DEFAULT 900,
    refresh_token_lifetime_seconds INT UNSIGNED NOT NULL DEFAULT 604800,
    maximum_failed_login_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 5,
    login_block_duration_seconds INT UNSIGNED NOT NULL DEFAULT 900,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT chk_policy_master_length
        CHECK (minimum_master_password_length >= 12),
    CONSTRAINT chk_policy_login_length
        CHECK (minimum_login_password_length BETWEEN 8 AND 128),
    CONSTRAINT chk_policy_rotation_days
        CHECK (secret_rotation_days >= 1),
    CONSTRAINT chk_policy_access_lifetime
        CHECK (access_token_lifetime_seconds BETWEEN 60 AND 86400)
) ENGINE = InnoDB;

-- Login lozinka se cuva samo kao Argon2id/Bcrypt hash.
-- Master lozinka se nikada ne cuva niti salje serveru.
CREATE TABLE IF NOT EXISTS users (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username                   VARCHAR(100) NOT NULL,
    email                      VARCHAR(254) NOT NULL,
    login_password_hash        VARCHAR(255) NULL,
    role                       ENUM('ADMIN', 'TEAM_LEAD', 'DEVELOPER') NOT NULL,
    status                     ENUM('PENDING', 'ACTIVE', 'FROZEN', 'DISABLED')
                               NOT NULL DEFAULT 'PENDING',
    mfa_enabled                BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts      SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until               TIMESTAMP(6) NULL,
    last_login_at              TIMESTAMP(6) NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_status (status)
) ENGINE = InnoDB;

-- Materijal potreban browseru da iz master lozinke izvede kljuc i otkljuca
-- privatni kljuc. Server vidi samo salt, KDF parametre, javni kljuc i sifrat.
CREATE TABLE IF NOT EXISTS user_crypto_material (
    user_id                    BIGINT UNSIGNED NOT NULL,
    kdf_algorithm              VARCHAR(30) NOT NULL DEFAULT 'PBKDF2-SHA-256',
    kdf_salt                   VARBINARY(64) NOT NULL,
    kdf_iterations             INT UNSIGNED NOT NULL,
    public_key_algorithm       VARCHAR(30) NOT NULL DEFAULT 'RSA-OAEP-3072',
    public_key_spki            MEDIUMBLOB NOT NULL,
    encrypted_private_key      MEDIUMBLOB NOT NULL,
    private_key_iv             VARBINARY(32) NOT NULL,
    private_key_algorithm      VARCHAR(30) NOT NULL DEFAULT 'AES-256-GCM',
    crypto_version             SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_crypto_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT chk_crypto_kdf_iterations CHECK (kdf_iterations >= 100000)
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS teams (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                       VARCHAR(150) NOT NULL,
    description                VARCHAR(500) NULL,
    created_by                 BIGINT UNSIGNED NOT NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_teams_name (name),
    CONSTRAINT fk_teams_creator FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE RESTRICT
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS team_memberships (
    team_id                    BIGINT UNSIGNED NOT NULL,
    user_id                    BIGINT UNSIGNED NOT NULL,
    team_role                  ENUM('LEAD', 'MEMBER') NOT NULL,
    joined_at                  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (team_id, user_id),
    KEY idx_team_memberships_user (user_id),
    CONSTRAINT fk_membership_team FOREIGN KEY (team_id)
        REFERENCES teams (id) ON DELETE CASCADE,
    CONSTRAINT fk_membership_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB;

-- Red sadrzi samo sifrovane podatke i minimalne serverske metapodatke.
-- Cak je i naziv tajne dio encrypted_blob vrijednosti.
CREATE TABLE IF NOT EXISTS secrets (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    owner_user_id              BIGINT UNSIGNED NOT NULL,
    team_id                    BIGINT UNSIGNED NULL,
    current_version_number     INT UNSIGNED NOT NULL DEFAULT 1,
    rotation_due_at            TIMESTAMP(6) NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    deleted_at                 TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    KEY idx_secrets_owner (owner_user_id),
    KEY idx_secrets_team (team_id),
    KEY idx_secrets_rotation_due (rotation_due_at),
    CONSTRAINT fk_secrets_owner FOREIGN KEY (owner_user_id)
        REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT fk_secrets_team FOREIGN KEY (team_id)
        REFERENCES teams (id) ON DELETE SET NULL
) ENGINE = InnoDB;

-- Svako azuriranje tajne pravi novu nepromjenjivu verziju sifrata.
CREATE TABLE IF NOT EXISTS secret_versions (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    secret_id                  BIGINT UNSIGNED NOT NULL,
    version_number             INT UNSIGNED NOT NULL,
    encrypted_blob             MEDIUMBLOB NOT NULL,
    encryption_iv              VARBINARY(32) NOT NULL,
    encryption_algorithm       VARCHAR(30) NOT NULL DEFAULT 'AES-256-GCM',
    created_by                 BIGINT UNSIGNED NOT NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_secret_version (secret_id, version_number),
    CONSTRAINT fk_version_secret FOREIGN KEY (secret_id)
        REFERENCES secrets (id) ON DELETE CASCADE,
    CONSTRAINT fk_version_creator FOREIGN KEY (created_by)
        REFERENCES users (id) ON DELETE RESTRICT
) ENGINE = InnoDB;

-- Envelope encryption: AES kljuc konkretne verzije tajne zasebno je omotan
-- javnim RSA-OAEP kljucem svakog korisnika koji ima pristup.
CREATE TABLE IF NOT EXISTS secret_key_envelopes (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    secret_version_id          BIGINT UNSIGNED NOT NULL,
    recipient_user_id          BIGINT UNSIGNED NOT NULL,
    wrapped_data_key           MEDIUMBLOB NOT NULL,
    wrapping_algorithm         VARCHAR(30) NOT NULL DEFAULT 'RSA-OAEP-3072',
    shared_by_user_id          BIGINT UNSIGNED NOT NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at                 TIMESTAMP(6) NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_envelope_recipient (secret_version_id, recipient_user_id),
    KEY idx_envelopes_recipient (recipient_user_id, revoked_at),
    CONSTRAINT fk_envelope_version FOREIGN KEY (secret_version_id)
        REFERENCES secret_versions (id) ON DELETE CASCADE,
    CONSTRAINT fk_envelope_recipient FOREIGN KEY (recipient_user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_envelope_sharer FOREIGN KEY (shared_by_user_id)
        REFERENCES users (id) ON DELETE RESTRICT
) ENGINE = InnoDB;

-- TOTP seed mora biti dostupan backendu radi provjere koda, ali je sifrovan
-- aplikacionim kljucem koji se cuva izvan baze (npr. environment varijabla).
CREATE TABLE IF NOT EXISTS user_mfa (
    user_id                    BIGINT UNSIGNED NOT NULL,
    encrypted_totp_secret      VARBINARY(512) NOT NULL,
    encryption_iv              VARBINARY(32) NOT NULL,
    confirmed_at               TIMESTAMP(6) NULL,
    last_used_time_step        BIGINT NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_mfa_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS oidc_identities (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id                    BIGINT UNSIGNED NOT NULL,
    issuer                     VARCHAR(500) NOT NULL,
    subject_identifier         VARCHAR(255) NOT NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_oidc_identity (issuer, subject_identifier),
    KEY idx_oidc_user (user_id),
    CONSTRAINT fk_oidc_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB;

-- U bazi se cuvaju samo hash vrijednosti nasumicnih session/refresh tokena.
CREATE TABLE IF NOT EXISTS sessions (
    id                         CHAR(36) NOT NULL,
    user_id                    BIGINT UNSIGNED NOT NULL,
    access_token_hash          BINARY(32) NOT NULL,
    refresh_token_hash         BINARY(32) NOT NULL,
    token_family_id            CHAR(36) NOT NULL,
    ip_address                 VARCHAR(45) NOT NULL,
    user_agent                 VARCHAR(500) NULL,
    access_expires_at          TIMESTAMP(6) NOT NULL,
    expires_at                 TIMESTAMP(6) NOT NULL,
    rotated_at                 TIMESTAMP(6) NULL,
    revoked_at                 TIMESTAMP(6) NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_session_access_hash (access_token_hash),
    UNIQUE KEY uq_session_refresh_hash (refresh_token_hash),
    KEY idx_sessions_user (user_id),
    KEY idx_sessions_family (token_family_id),
    KEY idx_sessions_expiry (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS authentication_attempts (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    username_attempted         VARCHAR(100) NULL,
    user_id                    BIGINT UNSIGNED NULL,
    ip_address                 VARCHAR(45) NOT NULL,
    outcome                    ENUM('SUCCESS', 'BAD_PASSWORD', 'BAD_MFA',
                                    'EXPIRED_TOKEN', 'BLOCKED') NOT NULL,
    occurred_at                TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_auth_attempt_ip_time (ip_address, occurred_at),
    KEY idx_auth_attempt_user_time (user_id, occurred_at),
    CONSTRAINT fk_auth_attempt_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS blocked_ip_addresses (
    ip_address                 VARCHAR(45) NOT NULL,
    reason                     VARCHAR(500) NOT NULL,
    blocked_until              TIMESTAMP(6) NOT NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (ip_address),
    KEY idx_blocked_ip_until (blocked_until)
) ENGINE = InnoDB;

-- Honeytokeni nisu povezani sa regularnim secrets endpointom niti UI prikazom.
-- Backend mora zamrznuti aktivnog korisnika ako demo upit vrati ovaj zapis.
CREATE TABLE IF NOT EXISTS honeytokens (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    decoy_name                 VARCHAR(255) NOT NULL,
    decoy_encrypted_blob       MEDIUMBLOB NOT NULL,
    fingerprint_hash           BINARY(32) NOT NULL,
    active                     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY uq_honeytoken_fingerprint (fingerprint_hash)
) ENGINE = InnoDB;

-- Kontrolni red odredjuje da li je izolovani SQL Injection demo privremeno aktivan.
CREATE TABLE IF NOT EXISTS honeypot_control (
    id                         TINYINT UNSIGNED NOT NULL,
    enabled_until              TIMESTAMP(6) NULL,
    enabled_by                 BIGINT UNSIGNED NULL,
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT chk_single_honeypot_control CHECK (id = 1),
    CONSTRAINT fk_honeypot_control_admin FOREIGN KEY (enabled_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB;

CREATE TABLE IF NOT EXISTS security_alerts (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id                    BIGINT UNSIGNED NULL,
    alert_type                 VARCHAR(80) NOT NULL,
    severity                   ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    ip_address                 VARCHAR(45) NULL,
    description                VARCHAR(1000) NOT NULL,
    acknowledged_by            BIGINT UNSIGNED NULL,
    acknowledged_at            TIMESTAMP(6) NULL,
    created_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    KEY idx_alerts_created (created_at),
    KEY idx_alerts_user (user_id),
    CONSTRAINT fk_alert_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_alert_ack_user FOREIGN KEY (acknowledged_by)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB;

-- Hash lanca racuna backend nad kanonskim zapisom:
-- entry_hash = SHA-256(previous_hash || canonical_event_data).
CREATE TABLE IF NOT EXISTS audit_logs (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id              BIGINT UNSIGNED NULL,
    event_type                 VARCHAR(100) NOT NULL,
    target_type                VARCHAR(80) NULL,
    target_id                  VARCHAR(100) NULL,
    ip_address                 VARCHAR(45) NULL,
    event_data                 JSON NOT NULL,
    occurred_at                TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    previous_hash              BINARY(32) NULL,
    entry_hash                 BINARY(32) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_audit_entry_hash (entry_hash),
    KEY idx_audit_actor_time (actor_user_id, occurred_at),
    KEY idx_audit_event_time (event_type, occurred_at),
    CONSTRAINT fk_audit_actor FOREIGN KEY (actor_user_id)
        REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB;

-- Jedan red sluzi backendu za transakcijsko zakljucavanje (SELECT ... FOR UPDATE)
-- pri dodavanju sljedeceg audit zapisa.
CREATE TABLE IF NOT EXISTS audit_chain_state (
    id                         TINYINT UNSIGNED NOT NULL,
    last_audit_log_id          BIGINT UNSIGNED NULL,
    last_hash                  BINARY(32) NULL,
    updated_at                 TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                                                   ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT chk_single_audit_chain CHECK (id = 1),
    CONSTRAINT fk_chain_last_log FOREIGN KEY (last_audit_log_id)
        REFERENCES audit_logs (id) ON DELETE RESTRICT
) ENGINE = InnoDB;

INSERT INTO security_policies (
    id,
    minimum_master_password_length,
    secret_rotation_days,
    access_token_lifetime_seconds,
    refresh_token_lifetime_seconds,
    maximum_failed_login_attempts,
    login_block_duration_seconds
)
VALUES (1, 14, 90, 900, 604800, 5, 900)
ON DUPLICATE KEY UPDATE id = id;

INSERT INTO audit_chain_state (id, last_audit_log_id, last_hash)
VALUES (1, NULL, NULL)
ON DUPLICATE KEY UPDATE id = id;

-- Audit log je append-only i kroz aplikacioni DB nalog se ne moze mijenjati
-- niti brisati. MySQL administrator i dalje moze ukloniti trigere, pa se za
-- jacu garanciju hash vrh lanca periodično izvozi/potpisuje izvan baze.
DROP TRIGGER IF EXISTS trg_audit_logs_no_update;
DROP TRIGGER IF EXISTS trg_audit_logs_no_delete;

DELIMITER $$

CREATE TRIGGER trg_audit_logs_no_update
BEFORE UPDATE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Audit log records are immutable';
END$$

CREATE TRIGGER trg_audit_logs_no_delete
BEFORE DELETE ON audit_logs
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Audit log records are immutable';
END$$

DELIMITER ;
