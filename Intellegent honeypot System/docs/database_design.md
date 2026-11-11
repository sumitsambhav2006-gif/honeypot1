# Database Architecture & Entity-Relationship Design

## 1. Relational Model Overview
IHTIP utilizes a 3NF normalized relational schema designed for MySQL 8.0+ (with SQLite fallback for local developer workstations).

### Entity Relationship Diagram
```
  ┌──────────┐         ┌───────────┐
  │  USERS   │         │ HONEYPOTS │
  └──────────┘         └─────┬─────┘
                             │ 1
                             │
                             │ hosts
                             │
                             ▼ *
┌───────────┐ 1       * ┌───────────┐ 1       * ┌──────────┐
│ ATTACKERS ├──────────►│ SESSIONS  ├──────────►│ COMMANDS │
└─────┬─────┘           └─────┬─────┘           └──────────┘
      │ 1                     │ 1
      │ generates             │ contains
      ▼ *                     ▼ *
┌───────────┐ 1       * ┌───────────┐
│  ALERTS   │◄──────────┤ATTACK_EVTS│
└───────────┘ triggers  └───────────┘
```

## 2. Table Specifications & Indexes

| Table Name | Primary Key | Key Indexes | Purpose |
|---|---|---|---|
| `users` | `id` | `idx_users_username` | Operator credentials & RBAC |
| `honeypots` | `id` | `idx_honeypots_status` | Deployed sensor nodes |
| `attackers` | `id` | `idx_attackers_ip`, `reputation`, `last_seen` | Attacker telemetry & enrichment |
| `sessions` | `id` | `idx_sessions_uuid`, `start_time`, `risk_score` | Interactive attacker sessions |
| `attack_events`| `id` | `idx_events_type`, `session_id`, `timestamp` | Normalized Cowrie security events |
| `commands` | `id` | `idx_commands_session`, `category` | Captured shell inputs |
| `alerts` | `id` | `idx_alerts_severity`, `status`, `timestamp` | SOC incident queue |

## 3. Indexing & Optimization Rationale
- **IP Address Indexing:** `attackers.source_ip` is indexed to enable sub-millisecond lookups during high-frequency credential stuffing attacks.
- **Timestamp Indexing:** Enables rapid timeseries filtering for Chart.js daily/hourly trend queries without full table scans.
- **UUID Indexing:** `sessions.session_id` allows immediate cross-referencing between raw logs and reconstructed forensic timelines.

