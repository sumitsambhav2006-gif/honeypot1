#!/bin/bash
# ==============================================================================
# IHTIP - Automated Database & Log Backup Script
# ==============================================================================
set -e

BACKUP_DIR="/var/backups/ihtip"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_NAME="honeypot_db"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

echo "[*] Starting IHTIP Database Backup ($TIMESTAMP)..."
if command -v mysqldump &> /dev/null; then
    mysqldump -u root -p"$DB_PASSWORD" "$DB_NAME" | gzip > "$BACKUP_DIR/db_${DB_NAME}_${TIMESTAMP}.sql.gz"
    echo "[+] MySQL database dumped to $BACKUP_DIR/db_${DB_NAME}_${TIMESTAMP}.sql.gz"
else
    # SQLite fallback
    if [ -f "/opt/intelligent-honeypot-platform/data/honeypot.db" ]; then
        gzip -c "/opt/intelligent-honeypot-platform/data/honeypot.db" > "$BACKUP_DIR/sqlite_${TIMESTAMP}.db.gz"
        echo "[+] SQLite database archived to $BACKUP_DIR/sqlite_${TIMESTAMP}.db.gz"
    fi
fi

# Archive raw Cowrie logs
LOG_FILE="/var/log/cowrie/cowrie.json"
if [ -f "$LOG_FILE" ]; then
    gzip -c "$LOG_FILE" > "$BACKUP_DIR/cowrie_logs_${TIMESTAMP}.json.gz"
    echo "[+] Cowrie raw logs archived."
fi

# Prune old backups older than retention window
find "$BACKUP_DIR" -type f -name "*.gz" -mtime +$RETENTION_DAYS -delete
echo "[+] Retention check complete. Backups older than $RETENTION_DAYS days removed."

