CREATE DATABASE IF NOT EXISTS ai_ids
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE ai_ids;

CREATE TABLE IF NOT EXISTS alerts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NULL,
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    description TEXT NOT NULL,
    PRIMARY KEY (id),
    INDEX idx_alerts_timestamp (timestamp),
    INDEX idx_alerts_attack_type (attack_type),
    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_source_ip (source_ip)
) ENGINE=InnoDB;
