-- =====================================================================
-- Intelligent Honeypot & Threat Intelligence Platform (IHTIP)
-- Normalized Production Database Schema (MySQL 8.0+)
-- =====================================================================

CREATE DATABASE IF NOT EXISTS `honeypot_db` 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `honeypot_db`;

-- 1. USERS TABLE (Dashboard & Analyst Access)
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(50) NOT NULL UNIQUE,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(20) NOT NULL DEFAULT 'analyst',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_login` DATETIME NULL,
    INDEX `idx_users_username` (`username`),
    INDEX `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. HONEYPOTS TABLE (Nodes & Services)
CREATE TABLE IF NOT EXISTS `honeypots` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(100) NOT NULL UNIQUE,
    `type` VARCHAR(50) NOT NULL DEFAULT 'cowrie-ssh',
    `ip_address` VARCHAR(45) DEFAULT '127.0.0.1',
    `port` INT DEFAULT 2222,
    `status` VARCHAR(20) DEFAULT 'active',
    `last_heartbeat` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_honeypots_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. ATTACKERS TABLE (Threat Actor / Source IPs & Enrichment)
CREATE TABLE IF NOT EXISTS `attackers` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `source_ip` VARCHAR(45) NOT NULL UNIQUE,
    `country` VARCHAR(100) DEFAULT 'Unknown',
    `country_code` VARCHAR(10) DEFAULT 'XX',
    `city` VARCHAR(100) DEFAULT 'Unknown',
    `latitude` FLOAT NULL,
    `longitude` FLOAT NULL,
    `asn` VARCHAR(100) DEFAULT 'Unknown ASN',
    `isp` VARCHAR(150) DEFAULT 'Unknown ISP',
    `reputation` INT DEFAULT 50,
    `total_attacks` INT DEFAULT 0,
    `first_seen` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `last_seen` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_attackers_ip` (`source_ip`),
    INDEX `idx_attackers_reputation` (`reputation`),
    INDEX `idx_attackers_last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. ATTACK_EVENTS TABLE (Normalized Security Logs)
CREATE TABLE IF NOT EXISTS `attack_events` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `attacker_id` INT NOT NULL,
    `honeypot_id` INT NULL,
    `session_id` VARCHAR(64) NULL,
    `event_type` VARCHAR(100) NOT NULL,
    `username` VARCHAR(100) NULL,
    `password_masked` VARCHAR(100) NULL,
    `raw_payload` TEXT NULL,
    `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_events_type` (`event_type`),
    INDEX `idx_events_session` (`session_id`),
    INDEX `idx_events_timestamp` (`timestamp`),
    INDEX `idx_events_username` (`username`),
    CONSTRAINT `fk_events_attacker` FOREIGN KEY (`attacker_id`) REFERENCES `attackers` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_events_honeypot` FOREIGN KEY (`honeypot_id`) REFERENCES `honeypots` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. SESSIONS TABLE (Attacker Engagement Lifecycles)
CREATE TABLE IF NOT EXISTS `sessions` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `session_id` VARCHAR(64) NOT NULL UNIQUE,
    `attacker_id` INT NOT NULL,
    `honeypot_id` INT NULL,
    `start_time` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `end_time` DATETIME NULL,
    `duration_seconds` INT DEFAULT 0,
    `command_count` INT DEFAULT 0,
    `risk_score` INT DEFAULT 0,
    `status` VARCHAR(20) DEFAULT 'active',
    INDEX `idx_sessions_uuid` (`session_id`),
    INDEX `idx_sessions_start` (`start_time`),
    INDEX `idx_sessions_status` (`status`),
    INDEX `idx_sessions_risk` (`risk_score`),
    CONSTRAINT `fk_sessions_attacker` FOREIGN KEY (`attacker_id`) REFERENCES `attackers` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_sessions_honeypot` FOREIGN KEY (`honeypot_id`) REFERENCES `honeypots` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. COMMANDS TABLE (Captured Terminal Input & Categorization)
CREATE TABLE IF NOT EXISTS `commands` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `session_id` INT NOT NULL,
    `command` TEXT NOT NULL,
    `category` VARCHAR(50) DEFAULT 'General',
    `risk_points` INT DEFAULT 5,
    `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_commands_session` (`session_id`),
    INDEX `idx_commands_category` (`category`),
    INDEX `idx_commands_timestamp` (`timestamp`),
    CONSTRAINT `fk_commands_session` FOREIGN KEY (`session_id`) REFERENCES `sessions` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. ALERTS TABLE (Security Operations Center Triages)
CREATE TABLE IF NOT EXISTS `alerts` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `event_id` INT NULL,
    `attacker_id` INT NOT NULL,
    `severity` VARCHAR(20) NOT NULL,
    `risk_score` INT DEFAULT 0,
    `title` VARCHAR(255) NOT NULL,
    `description` TEXT NULL,
    `status` VARCHAR(20) DEFAULT 'open',
    `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_alerts_severity` (`severity`),
    INDEX `idx_alerts_status` (`status`),
    INDEX `idx_alerts_timestamp` (`timestamp`),
    CONSTRAINT `fk_alerts_event` FOREIGN KEY (`event_id`) REFERENCES `attack_events` (`id`) ON DELETE SET NULL,
    CONSTRAINT `fk_alerts_attacker` FOREIGN KEY (`attacker_id`) REFERENCES `attackers` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

