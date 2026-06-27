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
    -- Version 7: ML engine additions
    confidence DECIMAL(5, 4) NULL COMMENT 'ML model confidence score 0.0-1.0, NULL for rule-based alerts',
    ml_generated TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = ML engine alert, 0 = rule engine alert',
    PRIMARY KEY (id),
    INDEX idx_alerts_timestamp (timestamp),
    INDEX idx_alerts_attack_type (attack_type),
    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_source_ip (source_ip),
    INDEX idx_alerts_ml_generated (ml_generated)
) ENGINE=InnoDB;

-- Migration for existing deployments: add columns if they don't already exist
-- Run this block manually on an existing database:
--
--   ALTER TABLE alerts
--       ADD COLUMN IF NOT EXISTS confidence DECIMAL(5,4) NULL
--           COMMENT 'ML model confidence score 0.0-1.0, NULL for rule-based alerts',
--       ADD COLUMN IF NOT EXISTS ml_generated TINYINT(1) NOT NULL DEFAULT 0
--           COMMENT '1 = ML engine alert, 0 = rule engine alert',
--       ADD INDEX IF NOT EXISTS idx_alerts_ml_generated (ml_generated);